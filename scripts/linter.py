import argparse
import csv
import ipaddress
import os
import re
import sys

import yaml

ALL_ENTRIES = [
    "c2",
    "certificate_cname_re",
    "certificate_organizations",
    "certificates",
    "distribution",
    "name",
    "names",
    "packages",
    "type",
    "websites",
    "ios_bundles",
]


def check_ioc_format(fpath):
    """
    Check format of network.yaml file
    """
    success = True
    print("Checking {} format".format(fpath))
    with open(fpath) as f:
        r = yaml.load(f, Loader=yaml.BaseLoader)

    ips = []
    domains = []
    names = []
    websites = []
    bundles = []
    for entry in r:
        if "name" not in entry:
            print("Entry {} without name".format(", ".join(entry.get("names", []))))
            success = False

        if entry["name"] not in names:
            names.append(entry["name"])
        else:
            print("Duplicate name {}".format(entry["name"]))
            success = False
        if "names" in entry:
            for n in entry["names"]:
                if n != entry["name"]:
                    if n not in names:
                        names.append(n)
                    else:
                        print("Duplicate name {}".format(n))
                        success = False

        # packages
        if not isinstance(entry.get("packages", []), list):
            print("Invalid packages format for {}".format(entry["name"]))
            success = False

        # Certificates
        certs = []
        if not isinstance(entry.get("certificates", []), list):
            print("Invalid certificates format for {}".format(entry["name"]))
            success = False
        for cert in entry.get("certificates", []):
            if not re.match(r"^[A-F0-9]{40}", cert):
                print("Invalid certificate format: {}".format(cert))
                success = False
            if cert not in certs:
                certs.append(cert)
            else:
                print("Duplicated cert {}".format(cert))
                success = False

        if "type" not in entry:
            print("Missing app type for {}".format(entry.get("name", "")))
            success = False
        else:
            if entry.get("type", "") not in ["stalkerware", "watchware"]:
                print("Invalid type {} for {}".format(entry.get("type", ""), entry.get("name", "")))
                success = False

        # websites
        if not isinstance(entry.get("websites", []), list):
            print("Invalid websites format for {}".format(entry["name"]))
            success = False
        for w in entry.get("websites", []):
            if w in websites:
                print("Duplicated website {}".format(w))
                success = False
            websites.append(w)

        for ws in entry.get("websites", []):
            if not re.match(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$", ws):
                print("Invalid website {}".format(ws))
                success = False

        # C2 IPs
        c2 = entry.get("c2", {})
        for ip in c2.get("ips", []):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                print("Invalid IP address : {}".format(ip))
                success = False

            if ip not in ips:
                ips.append(ip)
            else:
                print("Duplicated IP {}".format(ip))
                success = False

        # C2 domains
        for d in c2.get("domains", []):
            if not re.match(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$", d):
                print("Invalid domain format {}".foramt(d))
                success = False

            if d not in domains:
                domains.append(d)
            else:
                print("Duplicated domain {}".format(d))
                success = False

        # Check certificate_organizations
        if not isinstance(entry.get("certificate_organizations", []), list):
            print("certificate_organizations must be a list for {}".format(entry.get("name", "")))
            success = False

        # Check ios_bundles
        if not isinstance(entry.get("ios_bundles", []), list):
            print("ios_bundles of {} must be a list".format(entry.get("name", "")))
            success = False

        for b in entry.get("ios_bundles", []):
            if b in bundles:
                print("Duplicated ios bundle: {}".format(b))
                success = False
            else:
                bundles.append(b)



        # Check entry names
        for key in entry:
            if key not in ALL_ENTRIES:
                print("Invalid attribute {} for {}".format(key, entry.get("name", "")))
                success = False

    return success


def check_samples_format(folder):
    """
    Check format of samples.csv
    """
    success = True
    print("Checking samples.csv format")

    with open(os.path.join(folder, "ioc.yaml")) as f:
        iocs = yaml.load(f, Loader=yaml.BaseLoader)
    names = []
    for app in iocs:
        names.append(app["name"])
        if "names" in app:
            names += app["names"]

    indicators = []
    with open(os.path.join(folder, "samples.csv")) as f:
        reader = csv.reader(f, delimiter=',')

        for row in reader:
            if row[0] == "SHA256":
                continue
            if not re.match(r"[a-f0-9]{64}", row[0]):
                print("Invalid SHA256 format : {}".format(row[0]))
                success = False
            if row[0] not in indicators:
                indicators.append(row[0])
            else:
                print("Duplicated sample {}".format(row[0]))
                success = False

            if row[2].strip() != "":
                # Certificate
                if not re.match(r"^[A-F0-9]{40}", row[2].strip()):
                    print("Invalid certificate format {}".format(row[2]))
                    success = False

            if row[4].strip() == "":
                print("No stalkerware name for {}".format(row[0]))
                success = False
            elif row[4] not in names:
                print("{} is not a valid stalkerware name".format(row[4]))
                success = False

    return success


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check indicators format")
    parser.add_argument("--folder", "-f", default=".", help="Indicator folder")
    args = parser.parse_args()

    if not os.path.isdir(args.folder):
        print("Invalid folder")
        sys.exit(1)

    success = check_ioc_format(os.path.join(args.folder, "ioc.yaml"))
    success = check_ioc_format(os.path.join(args.folder, "watchware.yaml"))
    success &= check_samples_format(args.folder)

    if success:
        print("All good, good work!")
        sys.exit(0)
    else:
        print("Oh noes, there are some issues")
        sys.exit(1)
