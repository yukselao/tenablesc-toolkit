import pandas as pd
from repository.config_database import configservice
import traceback
import requests
import json
import pandas as pd
import logging


logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S%z")
requests.packages.urllib3.disable_warnings()
logging.getLogger("urllib3").setLevel(logging.WARNING)


class Result:
    def __init__(self, data=None, status=None, error=None):
        self.data = data
        self.status = status
        self.error = error


class AssetDatabase:

    def __init__(self, config=configservice()):
        self.config = config
        self.database = self.initdb()
        self.asdict = self.asDict()
        self.df = pd.DataFrame(self.asdict)

    def getDataframe(self):
        return self.df

    def asDict(self):
        record_list = []
        for record in self.database:
            dataset = {}
            dataset["ip"] = record["ip"]
            dataset["owner"] = record["owner"]
            record_list.append(dataset)
        return record_list

    def get_owner(self, ip):
        db = self.df
        if db[db['ip'] == ip]["owner"].empty:
            return "default_user"
        else:
            return db[db['ip'] == ip]["owner"].values[0]

    def initdb(self):
        return [{
            "ip":"0.0.0.0/0",
            "owner":"aliokan"
        }]
    def show(self):
        self.db.to_markdown()
