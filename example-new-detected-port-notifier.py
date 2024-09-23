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




def main():
    scan_dir = './nessus-scan-results'

    if os.path.exists(scan_dir):
        shutil.rmtree(scan_dir)
    os.makedirs(scan_dir)

    vuln_manager = VulnMgmt(asset_database=assets.get_database())

    response = vuln_manager.get_scan_results(keyword="Host Discovery")

    for scan_data in response.dataset[0:2]:
        logging.info(scan_data)

        response = vuln_manager.scan_result_download(scan_data["id"], f'{scan_dir}/scan-result.zip')

        zip_file_path = f'{scan_dir}/scan-result.zip'

        with open(zip_file_path, 'wb') as file:
            file.write(response.dataframe)

        if extract_zip_file(zip_file_path, scan_dir):
            os.remove(zip_file_path)



    nfr = nessus_file_reader(scan_dir)
    dataset = nfr.get_new_detected_hosts()

    smtp_server = "1.1.1.1"
    smtp_port = 25
    from_email = "test@test.com.tr"
    to_email = "test@test.com.tr"

    email_sender = EmailSender(smtp_server, smtp_port, from_email, to_email)

    subject = "Test Başlığı"
    body_html = """
    <html>
    <head></head>
    <body>
        <h1>Tenable Security Center Notify Agent: New Detected Hosts</h1>
        {}
    </body>
    </html>
    """.format(email_sender.list_to_html_table(dataset))

    email_sender.send_email(subject, body_html)


if __name__ == "__main__":
    main()