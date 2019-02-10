import boto3
from datetime import datetime
import logging
import json
import os
import base64
from cgi import parse_header, parse_multipart
from io import BytesIO

# Initialize objects and set variables that are not invocation specific to
# exploit container reuse.
#log_level = os.environ.get('LOG_LEVEL', 'INFO')
log_level = 'DEBUG'
logging.root.setLevel(logging.getLevelName(log_level))
_logger = logging.getLogger(__name__)

s3_client = boto3.client('s3')
s3_bucket = os.environ.get('S3_BUCKET_NAME')

def binary_support(event,context):
    # TODO implement
    # second code with binary encoding
    c_type, c_data = parse_header(event['headers']['content-type'])
    c_data['boundary'] = bytes(c_data['boundary'], "utf-8")
    #print(event['body'])
    decodedData = base64.b64decode(event['body'])
    #print(decodedData)
    #data1 = BytesIO(bytes(event2['body'].decode('base64'), 'utf-8'))
    data = BytesIO(decodedData)
    form_data = parse_multipart(data, c_data)
    return {
        'statusCode': 200,
        'body': json.dumps(str(form_data['email']))
    }

'''
plain_event = {
    "resource": "/asset",
    "path": "/asset",
    "httpMethod": "POST",
    "headers": {
        "Accept": "*/*",
        "accept-encoding": "gzip, deflate",
        "cache-control": "no-cache",
        "content-type": "multipart/form-data; boundary=--------------------------357754388461537595692911",
        "Host": "e38xa2cy12.execute-api.eu-west-1.amazonaws.com",
        "Postman-Token": "87b1f669-3da6-4309-ae75-be33578e74de",
        "User-Agent": "PostmanRuntime/7.4.0",
        "X-Amzn-Trace-Id": "Root=1-5c32b73c-78674d9cca016f6fc4ebf84e",
        "X-Forwarded-For": "103.240.193.12",
        "X-Forwarded-Port": "443",
        "X-Forwarded-Proto": "https"
    },
    "multiValueHeaders": {
        "Accept": [
            "*/*"
        ],
        "accept-encoding": [
            "gzip, deflate"
        ],
        "cache-control": [
            "no-cache"
        ],
        "content-type": [
            "multipart/form-data; boundary=--------------------------357754388461537595692911"
        ],
        "Host": [
            "e38xa2cy12.execute-api.eu-west-1.amazonaws.com"
        ],
        "Postman-Token": [
            "87b1f669-3da6-4309-ae75-be33578e74de"
        ],
        "User-Agent": [
            "PostmanRuntime/7.4.0"
        ],
        "X-Amzn-Trace-Id": [
            "Root=1-5c32b73c-78674d9cca016f6fc4ebf84e"
        ],
        "X-Forwarded-For": [
            "103.240.193.12"
        ],
        "X-Forwarded-Port": [
            "443"
        ],
        "X-Forwarded-Proto": [
            "https"
        ]
    },
    "requestContext": {
        "resourceId": "galw6v",
        "resourcePath": "/asset",
        "httpMethod": "POST",
        "extendedRequestId": "THGRhHs_joEFSmQ=",
        "requestTime": "07/Jan/2019:02:19:40 +0000",
        "path": "/dev/asset",
        "accountId": "365559582082",
        "protocol": "HTTP/1.1",
        "stage": "dev",
        "domainPrefix": "e38xa2cy12",
        "requestTimeEpoch": 1546827580927,
        "requestId": "b067522b-1222-11e9-9f70-e9011a362eea",
        "domainName": "e38xa2cy12.execute-api.eu-west-1.amazonaws.com",
        "apiId": "e38xa2cy12"
    },
    "body": "----------------------------357754388461537595692911\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.cpp\"\r\nContent-Type: text/x-c\r\n\r\n#include <iostream>\n#include <stdio.h>\nusing namespace std;\nclass myclass\n{\n    private:\n        int x = 10;\n        int y = 20;\n\n    public:\n        myclass() {\n         printf(\"obj.x(%d) and obj.y(%d)\\n\", x, y );\n\n        }\n        void getMethod();// {printf(\"obj.x(%d) and obj.y(%d)\\n\", x, y );}\n\n     friend std::ostream& operator << (ostream& out, const myclass& myTest);\n     //friend void operator << (ostream& out, const myclass& myTest);\n\n};\n\nostream& operator <<(ostream& out, const myclass& myTest)\n{\n\treturn out << myTest.x;\n}\n\n/* wrong definition\nvoid operator <<(ostream& out, const myclass& myTest)\n{\n\t//return out << myTest.x;\n}\n/\n\nvoid myclass::getMethod()\n{\n         x = 20;\n         y = 30;\n        printf(\"obj.x(%d) and obj.y(%d)\\n\", x, y );\n}\n\nint main()\n{\n    myclass obj;\n    myclass test1,test2,test3;\n    cout << test1 << endl << test2 << endl << test3 << endl;\n    //cout << test1 << test2 << test3;\n    obj.getMethod();\n    //printf(\"obj.x(%d) and obj.y(%d)\\n\", obj.x, obj.y );\n}\n\r\n----------------------------357754388461537595692911\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\nvip83.dha@gmail.com\r\n----------------------------357754388461537595692911--\r\n",
    "isBase64Encoded": "false"
}
'''

def without_binary(event,context):
   # TODO implement
    _logger.info('Event received: {}'.format(json.dumps(event)))
    # first code without binary encoding
    string1 = str(event['headers'])
    if "content-type" in string1:
        headerKey = "content-type"
    elif "Content-Type" in string1:
        headerKey = "Content-Type"
    else:
        return {
            'statusCode': 415,
            'body': "Unsupported Media Type, Only multipart/form-data upload"
        }
    c_type, c_data = parse_header(event['headers'][headerKey])
    if c_type == 'multipart/form-data':
        c_data['boundary'] = bytes(c_data['boundary'], "utf-8")
        data = BytesIO(bytes(event['body'], 'utf-8'))
        form_data = parse_multipart(data, c_data)
        if not s3_bucket:
            return_string = "email=" + str(form_data['email']) + "-- bucket ="
        else:
            return_string = "email=" + str(form_data['email']) + "-- bucket =" + s3_bucket

        return {
            'statusCode': 200,
            'body': return_string,

        }
    else:
        return {
            'statusCode': 200,
            'body': "Only multipart/form-data upload is allowed",
        }

#print(without_binary(plain_event))
