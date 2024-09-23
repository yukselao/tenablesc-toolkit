import sys, os
import logging

logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S%z")
logging.getLogger("urllib3").setLevel(logging.WARNING)

def extract_zip_file(zip_file_path, extract_to):

    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            if zip_ref.testzip() is not None:
                logging.error("Zip dosyası bozuk.")
                return False
            zip_ref.extractall(extract_to)
        logging.info(f"{zip_file_path} başarıyla çıkarıldı.")
        return True
    except zipfile.BadZipFile:
        logging.error("Geçersiz zip dosyası.")
        return False