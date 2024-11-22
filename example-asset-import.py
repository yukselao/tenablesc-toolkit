#!/usr/bin/env python3
# -*- coding: utf-8 -*-

##
# Author: Ali Okan Yuksel
# Mail: ayuksel@tenable.com
# Date: 08.08.2024
##

from service.vulnerability_management import VulnMgmt
import logging, json, sys, hashlib
import polars as pl
from service.asset_database import assets
import ipaddress
import os
logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S%z")
logging.getLogger("urllib3").setLevel(logging.WARNING)

ASSET_PREFIX = os.getenv('ASSET_PREFIX', 'default_prefix_')


def is_valid_ip(ip_string):
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def main():
    vuln_manager = VulnMgmt()

    df = pl.read_csv('sample-data/project-x/asset_data_2.csv')
    asset_keys = {}
    # Satırları dolaşmak için iter_rows() kullan
    for row in df.iter_rows(named=True):
        ipaddr = row["[IpAddress]:Display Label"]
        
        # IP adresi geçerli değilse döngünün başına dön
        if not is_valid_ip(ipaddr):
            logging.warning(f"Geçersiz IP adresi: {ipaddr}")
            continue
            
        is_virtual = row["[IpAddress]:Node Is Virtual"]
        deployment_type = row["[IpAddress]:Environment"] + " (Environment)"
        application_group = row["[IpAddress]:Application Group"] + " (Application Group)"
        server_group = row["[IpAddress]:Server Group"] + " (Server Group)"
        application_owner = row["[IpAddress]:Application Owner."]+ " (Application Owner)"
        system_owner = row["[IpAddress]:System Owner"] + " (System Owner)"
        computer_location = row["[IpAddress]:Computer.Location"] + " (Location)"
        #logging.info(f"ipaddr: {ipaddr}, is_virtual: {is_virtual}, deployment_type: {deployment_type}, application_group: {application_group}, server_group: {server_group}, application_owner: {application_owner}, system_owner: {system_owner}, computer_location: {computer_location}")

        if 'Virtual' not in asset_keys:
                asset_keys['Virtual'] = []
        
        if deployment_type not in asset_keys:
            asset_keys[deployment_type] = []
        
        if application_group not in asset_keys:
            asset_keys[application_group] = []
            
        if server_group not in asset_keys:
            asset_keys[server_group] = []
            
        if application_owner not in asset_keys:
            application_owner = application_owner 
            asset_keys[application_owner] = []
            
        if system_owner not in asset_keys:
            system_owner = system_owner
            asset_keys[system_owner] = []
            
        if computer_location not in asset_keys:
            asset_keys[computer_location] = []

        if is_virtual == True:            
            asset_keys['Virtual'].append(ipaddr)

        if deployment_type not in asset_keys[deployment_type]:
            asset_keys[deployment_type].append(ipaddr)
            
        if application_group not in asset_keys[application_group]:
            asset_keys[application_group].append(ipaddr)
            
        if server_group not in asset_keys[server_group]:
            asset_keys[server_group].append(ipaddr)
        
        if application_owner not in asset_keys[application_owner]:
            application_owner = application_owner
            asset_keys[application_owner].append(ipaddr)
            
        if system_owner not in asset_keys[system_owner]:
            system_owner = system_owner
            asset_keys[system_owner].append(ipaddr)
        
        if computer_location not in asset_keys[computer_location]:
            asset_keys[computer_location].append(ipaddr)
    
    
    
    for asset_name in asset_keys:
        logging.info(f"{asset_name}: {asset_keys[asset_name]}")
        asset_id = vuln_manager.asset_exists(ASSET_PREFIX + asset_name)
        logging.info(f"Check if asset exists: {ASSET_PREFIX}{asset_name} -> asset_id: {asset_id}")
        if asset_id:
            logging.info(f"Asset already exists: {asset_name}")
            response = vuln_manager.update_asset(asset_id, ','.join(asset_keys[asset_name]))
            if response.status == 200:
                logging.info(f"Asset updated: {asset_name}")
            else:
                logging.error(f"Asset update failed: {asset_name}")
        else:
            response = vuln_manager.create_asset(ASSET_PREFIX + asset_name, ','.join(asset_keys[asset_name]))
            if response.status == 200:
                logging.info(f"Asset created: {asset_name}")
            else:
                logging.error(f"Asset creation failed: {asset_name}, {response.error}")
                


    #print(json.dumps(asset_keys, indent=4))

    # vuln_manager.was_create_scan()

if __name__ == "__main__":
    main()
