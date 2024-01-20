import json
from urllib.parse import parse_qs, urlparse,urlencode
import re
import base64
import boto3
import datetime
import urllib3
import os

instance_role_matcher = re.compile('([0-9]{12}):aws:ec2-instance:(i-[0-9|a-f]{17})')

def malformed_req(msg):
    return {
        'statusCode': 400,
        'body': msg
        
    }

def runtime_error(msg):
    return {
        'statusCode': 500,
        'body': msg
    }

def request_ok(msg):
    return {
        'statusCode': 200,
        'body': msg
    }

def other_error(code, msg):
    return {
        'statusCode': code,
        'body': msg
    }

def success(msg):
    return {
        'statusCode': 200,
        'body': json.dumps(msg)
    }

def getrolemapping():
    bucket = os.environ["ROLE_MAPPING_BUCKET"]
    s3 = boto3.resource('s3')
    obj = s3.Object(bucket, "map.json")
    return obj.get()['Body'].read().decode('utf-8')     

def assume_role(account_id, instance_id, arn):
    session = boto3.Session()
    sts = session.client('sts')
    try:
        response = sts.assume_role(RoleArn=arn, RoleSessionName=instance_id, Tags=[{'Key': 'instanceId', 'Value': instance_id }, {'Key': 'accountId', 'Value': account_id}])  
        return 200, response 
    except Exception as e:
        return 401, "could not get creds"

def execute_presigned_request(url):
    http = urllib3.PoolManager()
    
    resp = http.request("GET", url, headers={"Accept": "application/json"})
    
    return (resp.status, resp.data)
    

def lambda_handler(event, context):
    # TODO implement
    if 'queryStringParameters' not in event:
        return malformed_req(f'Bad request')
        
    if 'presigned_url' not in event['queryStringParameters']:
        return malformed_req(f'presigned_url not present in request')
    
    ps = event['queryStringParameters']['presigned_url']
    psu = None
    try:
        psu = base64.b64decode(ps.encode('utf-8')).decode('utf-8')
    except:
        return malformed_req(f'presigned_url could not be decoded')

    parsed_url = None
    try:
        parsed_url = urlparse(psu)
    except:
        return malformed_req('cannot parse presigned url')

    if parsed_url.netloc.lower() != 'sts.amazonaws.com':
        return malformed_req(f'pre signed url not an sts url: {psu}')
    try:
        role_mapping = ""
        try:
            role_mapping = json.loads(getrolemapping())
        except Exception as e:
            print(e)
            return other_error(500, "Could not load instance role mapping file")

        allowed_headers = ['Version', 'X-Amz-Algorithm', 'X-Amz-Credential', 'X-Amz-Date', 'X-Amz-Expires', 'X-Amz-SignedHeaders', 'X-Amz-Security-Token', 'X-Amz-Signature']

        psu_params = parse_qs(parsed_url.query)

        ps = {'Action': 'GetCallerIdentity'}
        for k in allowed_headers:
            if k=='Action':
                continue
            if len(psu_params[k]) > 1:
                continue
            ps[k] = psu_params[k][0]
        
        
        sts_url = "https://sts.amazonaws.com/?"
        query_string = urlencode(ps)
        uu = sts_url + query_string
        status, response_str = execute_presigned_request(uu)
        if status != 200:
            return other_error(status, json.loads(response_str))

        response = None    
        try:
            response = json.loads(response_str)
        except Exception as e:
            return other_error(500, 'GetCallerIdentityResponse is invalid')

        if 'GetCallerIdentityResponse' not in response:
            return other_error(500, 'GetCallerIdentityResponse is invalid')
        if 'GetCallerIdentityResult' not in response['GetCallerIdentityResponse']:
            return other_error(500, 'GetCallerIdentityResponse is invalid')
        
        caller_id = response['GetCallerIdentityResponse']['GetCallerIdentityResult']
        
        if 'UserId' not in caller_id:
            return other_error(500, 'GetCallerIdentityResponse is invalid')
        
        user_id = caller_id['UserId']
        matches = instance_role_matcher.match(user_id)
        if not matches:
            return other_error(403, 'Please call with ec2 instance credentials')
        
        account_id = matches.group(1)
        instance_id = matches.group(2)
        if account_id not in role_mapping:
            return other_error(401, 'no role associated with this account or instance id')
        if instance_id not in role_mapping[account_id]:
            return other_error(401, 'no role associated with this account or instance id')

        arn = role_mapping[account_id][instance_id]
        status,creds = assume_role(account_id, instance_id, arn)
        if status != 200:
            return other_error(status, json.dumps(creds))
        try:
            c = creds['Credentials']
            c["Code"] = "Success"
            c["Type"] = "AWS-HMAC"
            c["LastUpdated"] = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
            
            # rename session token
            tok = c['SessionToken']
            c['Token'] = tok
            del c['SessionToken']

            # Reformat expiration
            exp = c['Expiration'].strftime('%Y-%m-%dT%H:%M:%SZ')
            c['Expiration'] = exp
            
            #c['Version'] = 1
            return success(c)
        except Exception as e:
            return other_error(status, e)
        return success(creds)

    except Exception as e:
        return runtime_error(e)

        
