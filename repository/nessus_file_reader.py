import xml.etree.ElementTree as ET
import pandas as pd
import sys
import logging as logger

logger.basicConfig(level=logger.DEBUG,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S%z")
logger.getLogger("urllib3").setLevel(logger.WARNING)


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

    # DataFrame'e çevir
    df = pd.DataFrame(report_hosts)
    return df

old_scan_file = sys.argv[1]
old_scan = get_dataframe(old_scan_file)

new_scan_file = sys.argv[2]

new_scan = get_dataframe(new_scan_file)


new_detected_ports_on_new_scan = pd.concat([new_scan, old_scan]).drop_duplicates(keep=False)

#undetected_ports_on_new_scan = pd.concat([old_scan, new_scan]).drop_duplicates(keep=False)

#logger.debug(new_detected_ports_on_new_scan.dtypes)
logger.info("Compare scan results: old scan file={}, new scan file={}".format( old_scan_file, new_scan_file))
logger.info("New Detected Ports and IP addresses on new scan file={}:".format(new_scan_file))
for index, row in new_detected_ports_on_new_scan.iterrows():
    logger.info(f"Host: {row['name']}, IP Address: {row['host_ip']}, Port: {row['port']}")

