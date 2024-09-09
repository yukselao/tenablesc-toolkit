


## Introduction:

The purpose of this project is to enable you to programmatically perform certain operations that are executed on the Tenable Security Center interface. 
## Prepare .env file first:

Create a file named .env. This file contains access information related to the Security Center environment you will be working on. To activate the definitions in the file, you must run the source .env command after each change.
### Sample ".env" file content: 
```
export TENABLE_SC_URL="<TENABLE_SC_URL>"
export TENABLE_SC_ACCESS_KEY="<TENABLE_SC_ACCESS_KEY>"
export TENABLE_SC_SECRET_KEY="<TENABLE_SC_SECRET_KEY>"
```


## Create Python Environment:

Run the following commands to define a project-specific virtual Python environment, install the dependencies, and activate the environment.

```bash
cd <project-folder>
python3 -m venv .venv
source .env
source .venv/bin/activate
pip3 install -r requirements.txt
./app.py
```



## Usecase 1: 

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
        response  = vuln_manager.create_web_app_scan(scan_name, "2", "1", "https://www.abc.com") # name, policy_id, zone, target_url
        if response.status == 200:
            logging.info(f"{scan_name} created successfully")
    '''
    '''Usecase 2: Create Oracle Credential Profile Dynamically'''


## Support
This project is provided as open-source for your use. You cannot receive official support from Tenable regarding this project. For any questions or bug reports, you can open an issue on GitHub.