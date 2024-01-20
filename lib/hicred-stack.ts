import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
// import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as iam from "aws-cdk-lib/aws-iam";
import * as S3Deployment from "aws-cdk-lib/aws-s3-deployment";

export class HicredStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);


    const bucket = new s3.Bucket(this, "instance-role-mapping");
    new S3Deployment.BucketDeployment(this, "ExampleMap", {
      sources: [S3Deployment.Source.asset("./role_mapping")],
      destinationBucket: bucket,
    });

    const myRole = new iam.Role(this, 'CredentialVendingExecutionRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    });

    const policy = new iam.ManagedPolicy(this, "AssumeAllRoles", {
      statements: [
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ["sts:AssumeRole", "sts:TagSession"],
          resources: ["*"]
        })
      ]
    });

    const readpolicy = new iam.ManagedPolicy(this, "ReadCredentialMap", {
      statements: [
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            "s3:Get*",
            "s3:List*",
            "s3:Describe*",
            "s3-object-lambda:Get*",
            "s3-object-lambda:List*"            
          ],
          resources: [bucket.bucketArn, bucket.bucketArn + "/*"]
        })
      ]
    });

    myRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("service-role/AWSLambdaBasicExecutionRole"));
    myRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("service-role/AWSLambdaVPCAccessExecutionRole")); // only required if your function lives in a VPC  
    myRole.addManagedPolicy(policy)
    myRole.addManagedPolicy(readpolicy)

    const handler = new lambda.Function(this, "CredentialVendingMachine", {
      runtime: lambda.Runtime.PYTHON_3_12,
      code: lambda.Code.fromAsset("resources"),
      handler: "cvlambda.lambda_handler",
      role: myRole,
      environment: {
        ROLE_MAPPING_BUCKET: bucket.bucketName
      }
    });


    const api = new apigateway.RestApi(this, "credential-vending-machine", {
      restApiName: "Instance Identity Based Credential Vending Service",
      description: "This service serves up credentials for great good.",
      endpointConfiguration: {
        types: [apigateway.EndpointType.EDGE]
      }
    });



    const lambdaIntegration = new apigateway.LambdaIntegration(handler, {
      requestTemplates: { "application/json": '{ "statusCode": "200" }' }
    });

    const credentialResource = api.root.addResource('credentials');

    credentialResource.addMethod('GET', lambdaIntegration);


  }
}
