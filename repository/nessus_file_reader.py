import xml.etree.ElementTree as ET
import pandas as pd
import sys, os
import logging

logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S%z")
logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_dataframe(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    report_hosts = []
    for report_host in root.findall('.//ReportHost'):

        plugin_ids = ['34277', '11219', '10335', '34220', '14663', '14274', '14272', '10180'] # https://www.tenable.com/plugins/nessus/families/Port%20scanners
        ports_list = []
        for report_item in report_host.findall('.//ReportItem'):
            plugin_id = report_item.get('pluginID')
            if plugin_id in plugin_ids:
                port = report_item.get('port')
                if port:
                    ports_list.append(port)


        for port in ports_list:
            host_data = {}
            host_data['name'] = report_host.get('name')  # ReportHost name attribute
            host_ip_tag = report_host.find('.//tag[@name="host-ip"]')
            if host_ip_tag is not None:
                host_data['host_ip'] = host_ip_tag.text
            else:
                host_data['host_ip'] = 'N/A'
            if port != '0':
                host_data['port'] = port
                report_hosts.append(host_data)

    df = pd.DataFrame(report_hosts)
    return df

def list_files_in_directory(directory):
    try:
        files = sorted(os.listdir(directory))
        if not files:
            logging.warning(f"{directory} içinde dosya bulunamadı.")
            return None, None
        old_file = os.path.join(directory, files[0])
        new_file = os.path.join(directory, files[-1])
        return old_file, new_file
    except Exception as e:
        logging.error(f"Dosyaları sıralarken hata oluştu: {e}")
        return None, None



class nessus_file_reader:

    def __init__(self, scan_dir):

        self.old_scan_file, self.new_scan_file = list_files_in_directory(scan_dir)
        self.old_scan = get_dataframe(self.old_scan_file)
        self.new_scan = get_dataframe(self.new_scan_file)

    def get_new_detected_hosts(self):

        new_detected_ports_on_new_scan = pd.concat([self.new_scan, self.old_scan]).drop_duplicates(keep=False)
        records = []
        for index, row in new_detected_ports_on_new_scan.iterrows():
            dataset = {}
            dataset["host"] = row["name"]
            dataset["host_ip"] = row["name"]
            dataset["port"] = row["port"]
            records.append(dataset)
        return records



