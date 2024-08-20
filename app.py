#!/usr/bin/env python3
# -*- coding: utf-8 -*-

##
# Author: Ali Okan Yuksel
# Mail: ayuksel@tenable.com
# Date: 08.08.2024
##

from service.vulnerability_management import VulnMgmt
import logging, json, sys, hashlib
import pandas as pd
from service.asset_database import assets
logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z")
logging.getLogger("urllib3").setLevel(logging.WARNING)

def main():
    vuln_manager = VulnMgmt(asset_database=assets.get_database())


    ''' Use-case 1: Create Web App Scan Policies Dynamically'''
    '''
    logging.info("Web App Scan Policies:")
    for policy in vuln_manager.get_was_policies().dataframe["response"]["usable"]:
        logging.info("Policy ID: {}, Policy Name: {}".format(policy["id"], policy["name"]))


    logging.info("Create Web App Scan:")
    scan_plan = [
        {"url": "https://www.abc1.com", "schedule": "20240808"},
        {"url": "https://www.abc2.com", "schedule": "20240808"},
        {"url": "https://www.abc3.com", "schedule": "20240808"},
        {"url": "https://www.abc4.com", "schedule": "20240808"},
        {"url": "https://www.abc5.com", "schedule": "20240808"},
        {"url": "https://www.abc6.com", "schedule": "20240808"}

    ]

    for scan_details in scan_plan:
        scan_name = "Web App Scan - " + scan_details["url"]
        response  = vuln_manager.create_web_app_scan(scan_name, "1000031", "1", "https://www.abc.com") # name, policy_id, zone, target_url
        if response.status == 200:
            logging.info(f"{scan_name} created successfully")
    '''
    '''Usecase 2: Create Oracle Credential Profile Dynamically'''
    df = pd.read_csv('oracle-profile.csv')
    for index, row in df.iterrows():
        profile_name = row["name"]
        dataset = {}
        dataset["name"] = row["name"]
        dataset["desc"] = row["desc"]
        dataset["port"] = row["port"]
        dataset["password"] = row["password"]
        dataset["user"] = row["user"]
        dataset["sid"] = row["sid"]
        response  = vuln_manager.create_oracle_credential_profile(values=dataset)
        if response.status == 200:
            logging.info(f"{profile_name} created successfully")





    #vuln_manager.was_create_scan()

if __name__ == "__main__":
    main()