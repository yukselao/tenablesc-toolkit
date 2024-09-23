import sys, os
import logging, shutil, zipfile

import logging

logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S%z")
logging.getLogger("urllib3").setLevel(logging.WARNING)

def extract_zip_file(zip_file_path, extract_to):

    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            if zip_ref.testzip() is not None:
                logging.error("Invalid zip file.")
                return False
            zip_ref.extractall(extract_to)
        logging.info(f"{zip_file_path} extracted successfully to {extract_to}")
        return True
    except zipfile.BadZipFile:
        logging.error("invalid zip file.")
        return False