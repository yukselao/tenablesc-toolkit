#!/usr/bin/env python3
# -*- coding: utf-8 -*-

##
# Author: Ali Okan Yuksel
# Mail: ayuksel@tenable.com
# Date: 23.03.2024
##



import logging, json, sys
import pandas as pd
logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z")
logging.getLogger("urllib3").setLevel(logging.WARNING)
from datetime import datetime, timedelta

from repository.config_database import configservice
import json, requests, traceback
import logging, json, sys

logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S%z")
logging.getLogger("urllib3").setLevel(logging.WARNING)


class Result:
    def __init__(self, url=None, data=None, status=None, error=None):
        self.url = url
        self.data = data
        self.status = status
        self.error = error


class SCParams:
    def __init__(self, filter=[], endoffset=99999):
        self.filter = filter
        self.endoffset = endoffset


class TenableSC:
    def __init__(self, config=configservice()):
        self.config = config
        self.url = config.get_tenable_sc_url()
        self.set_authentication_headers()

    def set_authentication_headers(self):
        self.headers = {"Accept": "application/json",
                        "X-APIKey": "accesskey={access_key}; secretkey={secret_key}".format(
                            access_key=self.config.get_tenable_sc_access_key(),
                            secret_key=self.config.get_tenable_sc_secret_key())}

    def scan_result_download(self, id, outputfile):
        try:
            url = f"{self.url}/rest/scanResult/{id}/download"
            response = requests.request("POST", url, headers=self.headers, verify=False)
            with open(outputfile, 'wb') as f:
                f.write(response.content)
                return Result(data=response.content, status=response.status_code, error=None)
        except Exception as err:
            return Result(data=None, status=None, error=str(traceback.format_exc()))

    def vuln_list(self, filter):
        try:
            payload = json.dumps({
                "query": {
                    "name": "",
                    "description": "",
                    "context": "",
                    "status": -1,
                    "createdTime": 0,
                    "modifiedTime": 0,
                    "groups": [],
                    "type": "vuln",
                    "tool": "listvuln",
                    "sourceType": "cumulative",
                    "startOffset": 0,
                    "endOffset": self.params.endoffset,
                    "filters": filter,
                    "vulnTool": "listvuln"
                },
                "sourceType": "cumulative",
                "columns": [],
                "type": "vuln"
            })
            url = f"{self.url}/rest/analysis"
            response = requests.request("POST", url, headers=self.headers, data=payload, verify=False)
            return Result(data=response.json(), status=response.status_code, error=None)

        except Exception as err:
            return Result(data=None, status=None, error=str(traceback.format_exc()))

    def create_oracle_credential_profile(self, name="", desc="", port="", password="", user="", sid=""):
        payload = json.dumps({
    "tags": "",
    "name": name,
    "description": desc,
    "context": "",
    "status": -1,
    "createdTime": 0,
    "modifiedTime": 0,
    "groups": [],
    "type": "database",
    "dbType": "Oracle",
    "source": "entry",
    "authType": "password",
    "port": port,
    "password": password,
    "oracleAuthType": "NORMAL",
    "oracle_service_type": "SID",
    "sid": sid,
    "login": user
})
        url = f"{self.url}/rest/credential"
        response = requests.request("POST", url, headers=self.headers, data=payload, verify=False)
        return Result(url=url, data=response.json(), status=response.status_code, error=None)


    def get_was_policies(self):
        try:
            url = f"{self.url}/rest/policy?limit=9999&startOffset=0&endOffset=9999&sortField=name&sortDirection=ASC&paginated=false&fields=name,description,tags,type,createdTime,ownerGroup,groups,owner,modifiedTime,policyTemplate,canUse,canManage,status&policyTemplate=40&filter=usable"
            response = requests.request("GET", url, headers=self.headers, verify=False)
            return Result(url=url, data=response.json(), status=response.status_code, error=None)
        except Exception as err:
            return Result(url=url, data=None, status=None, error=str(traceback.format_exc()))

    def create_web_app_scan(self, name, policy_id, zone, target_url, scan_desc ):
        try:
            url = f"{self.url}/rest/wasScan"
            payload =json.dumps({
  "name": name,
  "description": scan_desc,
  "context": "",
  "status": -1,
  "createdTime": 0,
  "modifiedTime": 0,
  "groups": [],
  "repository": {
    "id": 2
  },
  "schedule": {
    "start": "TZID=Europe/Istanbul:20240808T093000",
    "repeatRule": "FREQ=TEMPLATE;INTERVAL=1",
    "type": "template",
    "enabled": "true"
  },
  "emailOnLaunch": "false",
  "emailOnFinish": "false",
  "reports": [],
  "type": "policy",
  "policy": {
    "id": policy_id
  },
  "zone": {
    "id": int(zone)
  },
  "timeoutAction": "rollover",
  "rolloverType": "template",
  "classifyMitigatedAge": 0,
  "credentials": [],
  "maxScanTime": "unlimited",
  "inactivityTimeout": 43200,
  "urlList": target_url
})
            url = f"{self.url}/rest/wasScan"
            response = requests.request("POST", url, headers=self.headers, data=payload, verify=False)
            return Result(url=url, data=response.json(), status=response.status_code, error=response.text)

        except Exception as err:
            return Result(url=url, data=None, status=None, error=str(traceback.format_exc()))

    def get_scan_results(self):
        try:
            payload = json.dumps({
            "query": {
                "name": "",
                "description": "",
                "context": "",
                "status": -1,
                "createdTime": 0,
                "modifiedTime": 0,
                "groups": [],
                "type": "vuln",
                "tool": "sumasset",
                "sourceType": "cumulative",
                "startOffset": 0,
                "endOffset": 50,
                "filters": [],
                "sortColumn": "score",
                "sortDirection": "desc",
                "vulnTool": "sumasset"
            },
            "sourceType": "cumulative",
            "sortField": "score",
            "sortDir": "desc",
            "columns": [],
            "type": "vuln"
            })
            start_time = str(int((datetime.now() - timedelta(weeks=3)).timestamp())) # 3 weeks ago
            url = f"{self.url}/rest/scanResult?startTime={start_time}&timeCompareField=createdTime&filter=optimizeCompletedScans%2Cusable&fields=canUse%2CcanManage%2Cowner%2Cgroups%2CownerGroup%2Cstatus%2Cname%2Cdetails%2CdiagnosticAvailable%2CimportStatus%2CcreatedTime%2CstartTime%2CfinishTime%2CimportStart%2CimportFinish%2Crunning%2CtotalIPs%2CscannedIPs%2CcompletedIPs%2CcompletedChecks%2CcompletedTargets%2CtotalTargets%2CtotalChecks%2CdataFormat%2CdownloadAvailable%2CdownloadFormat%2Crepository%2CresultType%2CresultSource%2CscanDuration%2CSCI%2CsciOrganization%2CresultsSyncID%2CretrievalStatus%2Corganization"
            response = requests.request("GET", url, headers=self.headers, data=payload, verify=False)
            return Result(url=url, data=response.json(), status=response.status_code, error=response.text)
        except Exception as err:
            return Result(url=url, data=None, status=None, error=str(traceback.format_exc()))
    def vuln_details(self, vuln_list_record):
        url = f"{self.url}/rest/analysis"
        protocol = {'ICMP': 1, 'TCP': 6, 'UDP': 17, 'Unknown': 0}
        if vuln_list_record["uuid"] != "":
            ip_filter = {
                "id": "uuid",
                "filterName": "uuid",
                "operator": "=",
                "type": "vuln",
                "isPredefined": True,
                "value": vuln_list_record["uuid"]
            }
        else:
            ip_filter = {
                "id": "ip",
                "filterName": "ip",
                "operator": "=",
                "type": "vuln",
                "isPredefined": True,
                "value": vuln_list_record["ip"]
            }

        payload = json.dumps({
            'query': {
                'name': '',
                'description': '',
                'context': '',
                'status': -1,
                'createdTime': 0,
                'modifiedTime': 0,
                'groups': [],
                'type': 'vuln',
                'tool': 'vulndetails',
                'sourceType': 'cumulative',
                'startOffset': 0,
                'endOffset': 30,
                'filters': [
                    ip_filter,
                    {
                        "id": "pluginID",
                        "filterName": "pluginID",
                        "operator": "=",
                        "type": "vuln",
                        "isPredefined": True,
                        "value": vuln_list_record["pluginID"]
                    },
                    {
                        "id": "repository",
                        "filterName": "repository",
                        "operator": "=",
                        "type": "vuln",
                        "isPredefined": True,
                        "value": [{"id": vuln_list_record["repository"]["id"]}]
                    }
                ],
                'vulnTool': 'vulndetails',
            },
            'sourceType': 'cumulative',
            'columns': [],
            'type': 'vuln',
        })
        try:
            response = requests.request("POST", url, headers=self.headers, data=payload, verify=False)
            return Result(data=response.json(), status=response.status_code, error=None)

        except Exception as err:
            return Result(data=None, status=None, error=str(traceback.format_exc()))

    def vuln_summary(self, params=SCParams()):
        try:
            self.base_filter = params.filter
            self.params = params
            payload = json.dumps({
                "query": {
                    "description": "",
                    "context": "",
                    "status": -1,
                    "createdTime": 0,
                    "modifiedTime": 0,
                    "groups": [],
                    "type": "vuln",
                    "tool": "sumid",
                    "sourceType": "cumulative",
                    "startOffset": 0,
                    "endOffset": params.endoffset,
                    "filters": params.filter,
                    "sortColumn": "severity",
                    "sortDirection": "desc"
                },
                "sourceType": "cumulative",
                "sortField": "severity",
                "sortDir": "desc",
                "columns": [],
                "type": "vuln"
            })
            url = f"{self.url}/rest/analysis"
            response = requests.request("POST", url, headers=self.headers, data=payload, verify=False)
            return Result(data=response.json(), status=response.status_code, error=None)

        except Exception as err:
            return Result(data=None, status=None, error=str(traceback.format_exc()))

