#!/usr/bin/python
from __future__ import print_function
import json
import base64
import os,logging
import requests
from random import randint
from time import sleep
import time
import boto3
from botocore.exceptions import ClientError
urllib3_logger = logging.getLogger('urllib3')
urllib3_logger.setLevel(logging.CRITICAL)



class aws():
    def get_secret(self):
        logging.info("Extracting API Keys from store")
        secret_name = os.environ["secret_name"]
        region_name = os.environ["aws_region"]
    
        # Create a Secrets Manager client
        session = boto3.session.Session()
        client = session.client(
            service_name='secretsmanager',
            region_name=region_name
        )
    
        try:
            get_secret_value_response = client.get_secret_value(
                SecretId=secret_name
            )
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'DecryptionFailureException':
                raise e
            elif e.response['Error']['Code'] == 'InternalServiceErrorException':
                raise e
            elif e.response['Error']['Code'] == 'InvalidParameterException':
                raise e
            elif e.response['Error']['Code'] == 'InvalidRequestException':
                raise e
            elif e.response['Error']['Code'] == 'ResourceNotFoundException':
                raise e
        else:
            
            if 'SecretString' in get_secret_value_response:
                secret = get_secret_value_response['SecretString']
                secret = json.loads(secret)
                return secret

class msft():
    def get_user_id(self,id):
        url = 'https://login.microsoftonline.com/'+os.environ["azure_tenantid"]+'/oauth2/v2.0/token'
        secret = aws()
        app_secret = secret.get_secret()
        api_key = app_secret["azure_secret"]
        data = {
            'grant_type': 'client_credentials',
            'client_id': os.environ["azure_clientid"],
            'scope': 'https://graph.microsoft.com/.default',
            'client_secret': api_key
        }
        r = requests.post(url, data=data)
        token = r.json().get('access_token')

        url = "https://graph.microsoft.com/v1.0/users/"+id+"?$select=userPrincipalName"
        
        headers = {
            'Content-Type' : 'application\json',
            'Authorization': 'Bearer {}'.format(token)
        }
        r = requests.get(url, headers=headers)
        result = r.json()
        return result

class Helix ():
    def send_helix(self,payload):
        secret = aws()
        secret = secret.get_secret()
        api_key=secret["helix_key"]
        url=os.environ["helix_url"]
        headers = { 
            'Authorization':api_key, 
            'Content-Type':'application/vnd.api+json'
        }
        payload = json.loads(json.dumps(payload))
        response = requests.post(url,headers=headers,json=payload)
        print ("Helix Post Status: "+str(response.status_code)+"for data ")
        print(payload)
        return response.status_code

class DoD():
    def proc_dod(self):
        sync_duration = int(os.environ["sync_dur"])
        secret = aws()
        secret = secret.get_secret()
        api_key = secret["dod_key"]
        now = int(time.time())
        end = now-sync_duration
        now = str(now)
        end = str(end) 
        url_telemetry = 'https://feapi.marketplace.apps.fireeye.com/telemetry?start_time='+end+'&end_time='+now
        headers = { 
            'feye-auth-key':api_key, 
            'Content-Type':'multipart/form-data',
            
        }

        session = requests.Session()
        response = session.get(url_telemetry,headers=headers)
        content_mime = response.headers.get("content-type").split(";", 1)[0]
        if content_mime == "application/json":
                api_resp = response.json()
                alerts = json.loads(json.dumps(api_resp))
                if(alerts["count"]!=0):
                    report_item_payload=[]
                    for alert in alerts['data']:
                        try:
                            if(alert['is_malicious']==True and alert["connector_information"]["connector_type"]=='teams'):
                                report_url = 'https://feapi.marketplace.apps.fireeye.com/reports/'+alert['report_id']
                                report_response = session.get(report_url,headers=headers)
                                report_item = json.loads(json.dumps(report_response.json()))
                                userid=report_item["connector_information"]["file_owner"]["id"]
                                get_user = msft()
                                user_principal = get_user.get_user_id(userid)
                                principal = user_principal["userPrincipalName"]
                                report_item["user_principalName"] = principal
                                report_item_payload.append(report_item)
                                
                        except:
                            print ("None SaaS Event Ignore");         
                        sleep(1)
                    helix = Helix()
                    helix = helix.send_helix(report_item_payload)
                else:
                    print ("No events to upload to Helix\n")
def lambda_handler(event, context):
    get_dod = DoD()
    dod_rep = get_dod.proc_dod()
          
