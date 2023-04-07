from email import message
import logging
import json
import azure.functions as func
import os
import requests
import random
import string


def AccessToken(cred, resource):
    url = "https://login.microsoftonline.com/{}/oauth2/token".format(
        cred[0])
    data = {
        'grant_type': 'client_credentials',
        'Client_Id': '{}'.format(cred[1]),
        'Client_Secret': '{}'.format(cred[2]),
        'resource': resource
    }
    try:
        resp = requests.post(url=url, data=data)
        if "access_token" in resp.text:
            token = eval(resp.text)['access_token']
            return token
    except:
        print("Exception Occured in Access Token : ", resp.text)


def CreateUser(message, accessToken, tenant):
    url = "https://graph.microsoft.com/v1.0/users"
    id = []
    for user in message["users"]:
        randomPass = ''.join(random.choices(
            string.ascii_uppercase + string.ascii_lowercase + string.digits, k=12))
        logging.info(randomPass)
        CompanyEmail = user["CompanyEmail"]
        Username = CompanyEmail.split("@")
        NickName = Username[0]
        upn = NickName + tenant
        logging.info(upn)
        Workload=user["Workload"]
        WorkloadString=(Workload).replace(" ","")
        NickName = ''.join(random.choices(string.ascii_lowercase, k=8))
        Flag = 0
        while(Flag<10):
            try:
                data = json.dumps(
                    {
                        "accountEnabled": True,
                        "displayName": user["Name"],
                        "mailNickname": NickName,
                        "userPrincipalName": upn,
                        "passwordProfile": {
                            "forceChangePasswordNextSignIn": True,
                            "password": randomPass
                        }
                    }
                )
                headers = {'authorization': 'Bearer {}'.format(
                    accessToken), 'Content-type': 'application/json'}
                resp = requests.post(
                    url=url, headers=headers, data=data, verify=False)
                print(resp.text)
                if resp.ok:
                    Flag=11
                else:
                    randomPass = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=12))
                    logging.info("retrying with new password")
                    logging.info("New:- "+randomPass)
                    Flag=1+Flag
            except:
                logging.info("retrying with new password")
                randomPass = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=12))
                logging.info("New:- "+randomPass)
                Flag=1+Flag
        logging.info(resp.text)
        IDjson = json.loads(resp.text)
        id.append({
            "UPN": "{}".format(IDjson["userPrincipalName"]),
            "ObjectId": "{}".format(IDjson["id"]),
            "CompanyEmail": "{}".format(user["CompanyEmail"]),
            "password": randomPass,
            "Name":"{}".format(user["Name"])
        })
    # returnMessage=[]
    # returnMessage.append(id)
    returnMessagedict = {}
    returnMessagedict["Users"] = id
    returnMessagedict["approvedBy"] = message["approvedBy"]
    returnMessagedict["requestedBy"] = message["requestedBy"]
    returnMessagedict["tenantName"] = message["tenantName"]
    returnMessagedict["requestId"] = message["requestId"]
    returnMessagedict = json.dumps(returnMessagedict)
    logging.info(returnMessagedict)
    return returnMessagedict


def main(msg: func.QueueMessage, out: func.Out[func.QueueMessage]) -> None:
    logging.info('Python queue trigger function processed a queue item: %s',
                 msg.get_body().decode('utf-8'))
    jsonString = str(msg.get_body().decode('utf-8'))
    jsonObj = json.loads(jsonString)
    message = []
    cred = []
    if(jsonObj["tenantId"]=="2f2e0da1-0d79-4d2b-b60c-9e541463f9f9"):
        cred.append(os.environ["Tenant_Id2"])
        cred.append(os.environ["Client_Id2"])
        cred.append(os.environ["Client_Secret2"])
        accessToken = AccessToken(cred, 'https://graph.microsoft.com/')
        Message = CreateUser(jsonObj, accessToken,"@cloudseclab2.com")
    else:
        cred.append(os.environ["Tenant_Id"])
        cred.append(os.environ["Client_Id"])
        cred.append(os.environ["Client_Secret"])
        accessToken = AccessToken(cred, 'https://graph.microsoft.com/')
        Message = CreateUser(jsonObj, accessToken,"@cloudseclab.onmicrosoft.com")
        
    out.set(Message)
    logging.info(Message)
    logging.info("test")
