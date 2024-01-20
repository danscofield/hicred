# Host-Identity Based Credential Vending for EC2

***Disclaimer***: This is a proof of concept, please don't use it in production. I just wanted to use my own instance roles for Lightsail. Please use EC2 instance roles instead of this hackery! 

This is an example CDK stack implementing a credential vending machine based upon an EC2 instance's identity. A static file (`role_mapping/map.json`) defines a mapping from `(aws account id, ec2 instance id`) to a `role_arn`. A credential vending API verifies the account and instance ids of the caller, and returns an STS session for the associated `role_arn`. The credential format matches the instance metadata service format described [here](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#instance-metadata-security-credentials). The identity (i.e., account and instance ids) of the caller are verified by a bearer token strategy based upon pre-signing calls to `sts get-caller-identity` with EC2 [instance identity roles](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-identity-roles.html). 

The strategy works because the `GetCallerIdentityResult` has a unique `UserId` format when called with instance identity credentials that cannot be duplicated. Since STS is verifying the signature of this request, and the response contains the instance and account ids, this token is a strong indicator that the caller has access to the IMDS on that particular instance. This strategy has the additional benefit that the bearer token is ephemeral since STS credentials expire within 36 hours. 


```json
{
  "GetCallerIdentityResponse": {
    "GetCallerIdentityResult": {
      "Account": "ACCOUNTID",
      "Arn": "arn:aws:sts::ACCOUNTID:assumed-role/aws:ec2-instance/INSTANCEID",
      "UserId": "ACCOUNTID:aws:ec2-instance:INSTANCEID"
    },
    "ResponseMetadata": {
      "RequestId": "..."
    }
  }
}
```

To obtain a bearer token on an instance, query the IMDS to obtain instance identity credentials (e.g., `curl http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance`). Next, use these credentials to pre-sign a call to `sts get-caller-identity` and base64 encode the URL. This string can be used as a bearer token with the API (e.g., `curl https://endpoint/credentials?presigned_url=<XXX>`). Some example python code to generate a token is included below.

```python
import boto3
import base64
import json

http = urllib3.PoolManager()

resp = http.request("PUT", "http://169.254.169.254/latest/api/token", headers={"X-aws-ec2-metadata-token-ttl-seconds": 21600})
token = resp.data.decode('utf-8')

resp = http.request("GET", "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance", headers={"X-aws-ec2-metadata-token": token})
creds = json.loads(resp.data)

session = boto3.Session(aws_access_key_id=creds['AccessKeyId'], aws_secret_access_key=creds['SecretAccessKey'], aws_session_token=creds['Token'])
sts = session.client('sts')
psu = sts.generate_presigned_url('get_caller_identity', HttpMethod='GET')

print(base64.b64encode(psu.encode('utf-8')).decode('utf-8'))
```

When the API is called, a lambda (i.e., `resources/cvlambda.py`) decodes the bearer token, executes the pre-signed call, and extracts the account and instance ids. The lambda checks the static role mapping file in S3 (`role_mapping/map.json`) to find an associated role, assumes that role, and returns the result in IMDS format. The lambda passes the instance and role ids as requestTags during the `AssumeRole` call as a form of [confused deputy](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html) protection. An example trust policy for a role that uses these protections would be:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Statement1",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::STACK:role/LambdaExecutionRole"
            },
            "Action": [
                "sts:AssumeRole",
                "sts:TagSession"
            ],
            "Condition": {
                "StringEquals": {
                    "aws:RequestTag/accountId": "INSTANCE ACOCOUNT ID",
                    "aws:RequestTag/instanceId": "INSTANCE ID"
                }
            }
        }
    ]
}
```