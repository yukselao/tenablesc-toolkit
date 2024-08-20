


import os

class configservice:
    def __init__(self):
        self.smax_api_auth_url = os.getenv("SMAX_TENABLE_API_AUTH_URL")
        self.smax_api_url = os.getenv("SMAX_TENABLE_API_URL")
        self.smax_api_username = os.getenv("SMAX_TENABLE_API_USER")
        self.smax_api_password = os.getenv("SMAX_TENABLE_API_PASSWORD")

        self.initialize_cmdb_config_vars()

        self.initialize_tenable_sc_config_vars()

    def initialize_cmdb_config_vars(self):
        self.cmdb_url = os.getenv("CMDB_URL")
        self.cmdb_auth_key = os.getenv("CMDB_AUTH_KEY")

    def initialize_tenable_sc_config_vars(self):
        self.tenable_sc_url = os.getenv("TENABLE_SC_URL")
        self.tenable_sc_access_key = os.getenv("TENABLE_SC_ACCESS_KEY")
        self.tenable_sc_secret_key = os.getenv("TENABLE_SC_SECRET_KEY")

    def get_cmdb_url(self):
        return self.cmdb_url

    def get_cmdb_auth_key(self):
        return self.cmdb_auth_key

    def get_tenable_sc_url(self):
        return self.tenable_sc_url

    def get_tenable_sc_access_key(self):
        return self.tenable_sc_access_key

    def get_tenable_sc_secret_key(self):
        return self.tenable_sc_secret_key

    def get_smax_api_url(self):
        return self.smax_api_url

    def get_smax_api_auth_url(self):
        return self.smax_api_auth_url

    def get_smax_api_username(self):
        return self.smax_api_username

    def get_smax_api_password(self):
        return self.smax_api_password

