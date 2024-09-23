#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from service.vulnerability_management import VulnMgmt
import logging, os, shutil, zipfile
from service.asset_database import assets

logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S%z")
logging.getLogger("urllib3").setLevel(logging.WARNING)
from repository.nessus_file_reader import nessus_file_reader
from repository.smtp_operations import EmailSender


def main():
    logging("app started, check example python files")

if __name__ == "__main__":
    main()