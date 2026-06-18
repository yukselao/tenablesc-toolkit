#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Derive two comparable .nessus files (first-scan / last-scan) from 889.nessus so
that the UI's "Compare Nessus Scans" feature exercises all three scenarios:

  * Newly Detected Hosts  -> host present in last-scan but NOT in first-scan
  * New Detected Ports    -> host in both, but last-scan exposes an extra port
  * Unreachable Hosts     -> host present in first-scan but NOT in last-scan

Run from the repo root:  python3 sample-data/compare-scenarios/generate_samples.py
"""
import copy
import os
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "..", "889.nessus")

# Host selections (IPs as they appear in 889.nessus)
FIRST_HOSTS = ["10.10.10.11", "10.10.10.53", "10.10.10.52", "10.10.10.99", "10.10.10.66", "10.10.10.55"]
# last-scan: drop .55 (unreachable), keep the rest, add extra port to .11,
# and introduce a brand-new host .200 cloned from .53 (newly detected).
LAST_HOSTS = ["10.10.10.11", "10.10.10.53", "10.10.10.52", "10.10.10.99", "10.10.10.66"]

NEW_HOST_IP = "10.10.10.200"
NEW_HOST_CLONE_OF = "10.10.10.53"
EXTRA_PORT_HOST = "10.10.10.11"
EXTRA_PORTS = ["8080", "3389"]  # ports added only in last-scan


def load_hosts():
    tree = ET.parse(SOURCE)
    root = tree.getroot()
    report = root.find(".//Report")
    hosts = {rh.get("name"): rh for rh in report.findall("ReportHost")}
    return tree, root, report, hosts


def build(tree, report, host_elems, out_path):
    """Replace the Report's ReportHost children with the given (deep-copied) ones."""
    new_root = copy.deepcopy(tree.getroot())
    new_report = new_root.find(".//Report")
    for rh in list(new_report.findall("ReportHost")):
        new_report.remove(rh)
    for he in host_elems:
        new_report.append(copy.deepcopy(he))
    ET.ElementTree(new_root).write(out_path, encoding="UTF-8", xml_declaration=True)
    print(f"  wrote {out_path}  ({len(host_elems)} hosts)")


def set_host_ip(rh, new_ip):
    """Rename a ReportHost and its identifying tags to a new IP."""
    rh.set("name", new_ip)
    hp = rh.find("HostProperties")
    for tag in hp.findall("tag"):
        if tag.get("name") in ("host-ip", "host-rdns"):
            tag.text = new_ip
        if tag.get("name") == "host-fqdns":
            tag.text = ('[{"FQDN":"%s","sources":["get_host_fqdn()"]}]' % new_ip)


def add_ports(rh, ports):
    hp = rh.find("HostProperties")
    for p in ports:
        tag = ET.SubElement(hp, "tag")
        tag.set("name", f"enumerated-ports-{p}-tcp")
        tag.text = "open"


def main():
    tree, root, report, hosts = load_hosts()

    # ---- first-scan ----
    first_elems = [hosts[ip] for ip in FIRST_HOSTS]
    build(tree, report, first_elems, os.path.join(HERE, "first-scan.nessus"))

    # ---- last-scan ----
    last_elems = []
    for ip in LAST_HOSTS:
        he = copy.deepcopy(hosts[ip])
        if ip == EXTRA_PORT_HOST:
            add_ports(he, EXTRA_PORTS)
        last_elems.append(he)
    # newly detected host cloned from an existing one, re-IP'd
    new_host = copy.deepcopy(hosts[NEW_HOST_CLONE_OF])
    set_host_ip(new_host, NEW_HOST_IP)
    last_elems.append(new_host)
    build(tree, report, last_elems, os.path.join(HERE, "last-scan.nessus"))

    print("\nExpected analysis result:")
    print(f"  Newly Detected Hosts : {NEW_HOST_IP}")
    print(f"  New Detected Ports   : {EXTRA_PORT_HOST} -> {', '.join(p + '/tcp' for p in EXTRA_PORTS)}")
    print(f"  Unreachable Hosts    : 10.10.10.55")


if __name__ == "__main__":
    main()
