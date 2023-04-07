import datetime
import json
import logging
import os
import time

import azure.functions as func
import requests


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


def createRG(accessToken, SubId, RGName):
    url = "https://management.azure.com/subscriptions/{}/resourcegroups/{}?api-version=2021-04-01".format(
        SubId, RGName)
    headers = {'authorization': 'Bearer {}'.format(
        accessToken), 'Content-type': 'application/json'}
    data = json.dumps(
        {
            "location": "eastus"
        }
    )
    logging.info(data)
    resp = requests.put(url=url, headers=headers, data=data, verify=False)
    print(resp.text)
    logging.info(resp.text)


def createBudget(accessToken, SubId, RGName, amount, contactEmail, days):
    startdate = datetime.datetime.now().replace(
        microsecond=0).replace(day=1).isoformat() + "Z"
    c = datetime.datetime.now() + datetime.timedelta(days=days)
    enddate = c.replace(microsecond=0).isoformat() + "Z"
    url = "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Consumption/budgets/{}auto?api-version=2021-10-01".format(
        SubId, RGName, RGName)
    headers = {'authorization': 'Bearer {}'.format(
        accessToken), 'Content-type': 'application/json'}
    data = json.dumps(
        {
            "properties": {
                "category": "Cost",
                "amount": amount,
                "timeGrain": "Monthly",
                "timePeriod": {
                    "startDate": "{}".format(startdate),
                    "endDate": "{}".format(enddate)
                },
                "notifications": {
                    "Actual_GreaterThan_80_Percent": {
                        "enabled": True,
                        "operator": "GreaterThan",
                        "threshold": 80,
                        "locale": "en-us",
                        "contactEmails": [
                            "shdahiya@deloitte.com",
                            "{}".format(contactEmail)
                        ],
                        "thresholdType": "Actual"
                    }
                }
            }
        }
    )
    logging.info(data)
    resp = requests.put(url=url, headers=headers, data=data, verify=False)
    print(resp.text)
    logging.info(resp.text)


def assignTag(accessToken, SubId, RGName, EffortName, WBS,requestedBy):
    url = "https://management.azure.com/subscriptions/{}/resourcegroups/{}/providers/Microsoft.Resources/tags/default?api-version=2021-04-01".format(
        SubId, RGName)
    headers = {'authorization': 'Bearer {}'.format(
        accessToken), 'Content-type': 'application/json'}
    data = json.dumps(
        {
            "properties": {
                "tags": {
                    "EffortName": EffortName,
                    "EffortWBS": WBS,
                    "Owner": requestedBy
                }
            }
        }
    )
    logging.info(data)
    resp = requests.put(url=url, headers=headers, data=data, verify=False)
    print(resp.text)
    logging.info(resp.text)


def main(msg: func.QueueMessage, out: func.Out[func.QueueMessage]) -> None:
    logging.info('Python queue trigger function processed a queue item: %s',
                 msg.get_body().decode('utf-8'))
    jsonString = str(msg.get_body().decode('utf-8'))
    jsonObj = json.loads(jsonString)
    
    cred = []
    if(jsonObj["tenantId"]=="2f2e0da1-0d79-4d2b-b60c-9e541463f9f9"):
        cred.append(os.environ["Tenant_Id2"])
        cred.append(os.environ["Client_Id2"])
        cred.append(os.environ["Client_Secret2"])
    else:
        cred.append(os.environ["Tenant_Id"])
        cred.append(os.environ["Client_Id"])
        cred.append(os.environ["Client_Secret"])
    accessToken2 = AccessToken(cred, 'https://management.azure.com/')
    createRG(accessToken2, jsonObj["SubID"], jsonObj["RGName"])
    time.sleep(30)
    assignTag(accessToken2, jsonObj["SubID"],
                 jsonObj["RGName"], jsonObj["EffortName"], jsonObj["EffortWBS"],jsonObj["requestedBy"])
    createBudget(accessToken2, jsonObj["SubID"],
                 jsonObj["RGName"], jsonObj["Budget"],jsonObj["requestedBy"], jsonObj["Tenure"])
    out.set("{}".format(jsonString))