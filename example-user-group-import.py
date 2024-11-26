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
import os
logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S%z")
logging.getLogger("urllib3").setLevel(logging.WARNING)

ASSET_PREFIX = os.getenv('ASSET_PREFIX', 'default_prefix_')




def main():
    vuln_manager = VulnMgmt()
    asset_keys = {}

    # Pandas ile oku
    df = pd.read_csv('sample-data/project-x/dummy_adm_users.csv', encoding='utf-8')
    groups = {}
    for index, row in df.iterrows():
        name = str(row["givenName"] + " " + row["sn"])
        firstname = row["givenName"]
        lastname = row["sn"]
        username = str(row["sAMAccountName"])
        email = str(row["Mail"])
        group = str(row["Group"])
        
        userdata = {
            "name": name,
            "firstname": firstname,
            "lastname": lastname,
            "username": username,
            "email": email
        }
        
        logging.info(f"{group} - {name} - {username} - {email}")
        if group not in groups:
            groups[group] = []
        groups[group].append(userdata)



    # Pretty print kullanarak yazdır
    import pprint
    pp = pprint.PrettyPrinter(indent=4, width=120)
    pp.pprint(groups)
    
    
    sc_group_list = vuln_manager.get_group_list().dataframe
    sc_group_names = [group["name"] for group in sc_group_list]

    print(groups)
    
    for key in groups:
        if key in sc_group_names:
            logging.info(f"{key} already exists, skip group creation")
        else:
            logging.info(f"{key} does not exist, create group")
            result = vuln_manager.create_group(key)
            if result.status != 200:
                logging.error(result.error)
        for user_dataset in groups[key]:
            group_id = vuln_manager.get_group_id(key).dataframe
            user_dataset["group_id"] = group_id
            result = vuln_manager.create_user(user_dataset)
            print(result.dataframe)
            print(result.status)
            print(result.error)
            print(user_dataset)
        
    print(sc_group_list)

if __name__ == "__main__":
    main()
