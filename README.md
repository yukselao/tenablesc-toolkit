


## Introduction:

The purpose of this project is to enable you to programmatically perform certain operations that are executed on the Tenable Security Center interface. 
## Prepare .env file first:

Create a file named .env. This file contains access information related to the Security Center environment you will be working on. To activate the definitions in the file, you must run the source .env command after each change.

### Sample ".env" file content: 
```
export TENABLE_SC_URL="<TENABLE_SC_URL>"
export TENABLE_SC_ACCESS_KEY="<TENABLE_SC_ACCESS_KEY>"
export TENABLE_SC_SECRET_KEY="<TENABLE_SC_SECRET_KEY>"

export ASSET_PREFIX="COMPANY - "

##
#  The password defined below will be used as the default password when creating a user via the API. In the future, when the user's authentication method is set to LDAP, the user will be able to log in to the system using their Active Directory password. Initially, the default password should be used to access each user individually, allowing for default dashboard customization and other settings. Afterward, the user's authentication type should be set to LDAP.
##
export USER_DEFAULT_PASSWORD="Very_s3cure_P@ssw0rd_%o_o%"

###
# The definition of GROUP_DEFAULT_REPOSITORY_LIST may vary depending on the environment, so it has been set as a configuration parameter. You need to analyze the create JSON request sent to the rest/group REST API in the background when creating a group through the user interface, extract the relevant data, and add it here.
##
export GROUP_DEFAULT_REPOSITORY_LIST='[{"id": 9,"name": "Default","description": "","context": "","status": null,"createdTime": null,"modifiedTime": 1697471333,"dataFormat": "universal","type": "Local","trendingDays": "91","trendWithRaw": "true","ipRange": "0.0.0.0/0","organizations": [],"activeVulnsLifetime": null,"passiveVulnsLifetime": null,"mitigatedVulnsLifetime": null,"complianceVulnsLifetime": null,"lceVulnsLifetime": null,"markDelete": false},{"id": 8,"name": "Manual Audit","description": "","context": "","status": null,"createdTime": null,"modifiedTime": 1603748619,"dataFormat": "IPv4","type": "Offline","trendingDays": 0,"trendWithRaw": "true","ipRange": "0.0.0.0/0","organizations": [],"activeVulnsLifetime": null,"passiveVulnsLifetime": null,"mitigatedVulnsLifetime": null,"complianceVulnsLifetime": null,"lceVulnsLifetime": null,"markDelete": false,"mdm": {"id": {"name": "","description": "","context": "","status": -1,"createdTime": 0,"modifiedTime": 0}},"preferences": {}},{"id": 6,"name": "Tenable.OT","description": "","context": "","status": null,"createdTime": null,"modifiedTime": 1580421232,"dataFormat": "agent","type": "Local","trendingDays": "30","trendWithRaw": "true","ipRange": null,"organizations": [],"activeVulnsLifetime": null,"passiveVulnsLifetime": null,"mitigatedVulnsLifetime": null,"complianceVulnsLifetime": null,"lceVulnsLifetime": null,"markDelete": false}]'

## 
# $ getconf ARG_MAX:
# ARG_MAX represents the maximum length, in bytes, of the arguments and environment variables that can be passed to a new program by the exec functions in Unix-like operating systems. Specifically, it defines the maximum combined length of command-line arguments and environment variables that a process can receive.
# If this value is not too small, the definitions above will work without problems.
##

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

## Support
This project is provided as open-source for your use. You cannot receive official support from Tenable regarding this project. For any questions or bug reports, you can open an issue on GitHub.
