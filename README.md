


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
