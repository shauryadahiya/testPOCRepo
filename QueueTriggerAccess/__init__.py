import logging
import json
import azure.functions as func
import os
import requests
import datetime
import uuid


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


def grantADRoleToUser(accessToken, principalId, roleId, days):
    url = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests"
    headers = {'authorization': 'Bearer {}'.format(
        accessToken), 'Content-type': 'application/json'}
    startdate = datetime.datetime.now().replace(microsecond=0).isoformat() + "Z"
    c = datetime.datetime.now() + datetime.timedelta(days=days)
    enddate = c.replace(microsecond=0).isoformat() + "Z"
    data = json.dumps(
        {
            "action": "adminAssign",
            "justification": "Role assigned through automation",
            "roleDefinitionId": roleId,
            "directoryScopeId": "/",
            "principalId": principalId,
            "scheduleInfo": {
                "startDateTime": startdate,
                "expiration": {
                    "type": "afterDateTime",
                    "endDateTime": enddate,
                    "duration": None
                }
            }
        }
    )
    logging.info(data)
    resp = requests.post(url=url, headers=headers, data=data, verify=False)
    print("Role granted to user")
    logging.info(resp.text)


def grantResourceRoleToUser(accessToken, principalId, Scope, roleId, days):
    guid = str(uuid.uuid4())
    startdate = datetime.datetime.now().replace(microsecond=0).isoformat() + "Z"
    c = datetime.datetime.now() + datetime.timedelta(days=days)
    enddate = c.replace(microsecond=0).isoformat() + "Z"
    url = "https://management.azure.com/subscriptions/{}/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/{}?api-version=2020-10-01".format(
        Scope, guid)
    headers = {'authorization': 'Bearer {}'.format(
        accessToken), 'Content-type': 'application/json'}
    data = json.dumps(
        {
            "properties": {
                "principalId": "{}".format(principalId),
                "roleDefinitionId": "/subscriptions/{}/providers/Microsoft.Authorization/roleDefinitions/{}".format(Scope,roleId),
                "requestType": "AdminAssign",
                "scheduleInfo": {
                    "startDateTime": "{}".format(startdate),
                    "expiration": {
                        "type": "afterDateTime",
                        "endDateTime": enddate,
                        "duration": None
                    }
                }
            }
        }
    )
    logging.info(data)
    resp = requests.put(url=url, headers=headers, data=data, verify=False)
    print("Role granted to user")
    logging.info(resp.text)


def getUserPrincipalId(accessToken, upn):
    url = "https://graph.microsoft.com/v1.0/users/{}".format(upn)
    headers = {'authorization': 'Bearer {}'.format(accessToken)}
    resp = requests.get(url=url, headers=headers, verify=False)
    resp = json.loads(resp.text)
    return resp["id"]


def main(msg: func.QueueMessage, out: func.Out[func.QueueMessage]) -> None:
    logging.info('Python queue trigger function processed a queue item: %s',
                 msg.get_body().decode('utf-8'))
    jsonString = str(msg.get_body().decode('utf-8'))
    jsonObj = json.loads(jsonString)
    cred = []
    if(jsonObj["TenantId"]=="2f2e0da1-0d79-4d2b-b60c-9e541463f9f9"):
        cred.append(os.environ["Tenant_Id2"])
        cred.append(os.environ["Client_Id2"])
        cred.append(os.environ["Client_Secret2"])
    else:
        cred.append(os.environ["Tenant_Id"])
        cred.append(os.environ["Client_Id"])
        cred.append(os.environ["Client_Secret"])
    accessToken1 = AccessToken(cred, 'https://graph.microsoft.com/')
    logging.info(accessToken1)
    for role in jsonObj["ADRoles"]:
        for upn in jsonObj["PrincipalUPN"]:
            logging.info(upn)
            ObjectId = getUserPrincipalId(accessToken1, upn)
            days=int(role["days"])
            grantADRoleToUser(accessToken1, ObjectId, role["RoleId"], days)
    accessToken2 = AccessToken(cred, 'https://management.azure.com/')
    for role in jsonObj["AzureRoles"]:
        for upn in jsonObj["PrincipalUPN"]:
            logging.info(upn)
            ObjectId = getUserPrincipalId(accessToken1, upn)
            days=int(role["days"])
            Scope="{}/resourceGroups/{}".format(jsonObj["SubID"],jsonObj["RGName"])
            grantResourceRoleToUser(accessToken2, ObjectId,
                                    Scope, role["RoleId"], days)
    logging.info("test")
    out.set("{}".format(jsonString))
