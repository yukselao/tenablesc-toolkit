## 

## Prepare .env file first:

Create a file named .env. This file contains access information related to the Security Center environment you will be working on. To activate the definitions in the file, you must run the source .env command after each change.
### Sample ".env" file content: 
```
export TENABLE_SC_URL="<TENABLE_SC_URL>"<br />
export TENABLE_SC_ACCESS_KEY="<TENABLE_SC_ACCESS_KEY>"<br />
export TENABLE_SC_SECRET_KEY="<TENABLE_SC_SECRET_KEY>"<br />
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

For any questions or error reports, you can open a project-specific issue on GitHub.