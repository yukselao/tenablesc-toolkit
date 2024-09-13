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
    df = pd.read_csv('sample-data/web-app-scan-data.csv')
    for index, row in df.iterrows():
        scan_name = str(row["name"])
        scan_url = str(row["url"])
        was_policy_id = str(row["was_policy_id"])
        scan_zone_id = str(row["scan_zone_id"])
        scan_desc = "Source: tenablesc-toolkit"
        logging.info("scan_name: " + scan_name)
        logging.info("scan_url: " + scan_url)
        logging.info("was_policy_id: " + was_policy_id)
        logging.info("scan_zone_id: " + scan_zone_id)
        #  name, policy_id, zone, target_url
        response  = vuln_manager.create_web_app_scan(scan_name, was_policy_id, scan_zone_id, scan_url, scan_desc) # name, policy_id, zone, target_url
        if response.status == 200:
            logging.info(f"{scan_name} created successfully")
        else:
            logging.error(response.status)






    #vuln_manager.was_create_scan()

if __name__ == "__main__":
    main()