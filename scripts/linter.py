import yaml
import csv
import argparse
import os
import sys
import re
import ipaddress


def check_ioc_format(folder):
    """
    Check format of network.yaml file
    """
    success = True
    print("Checking ioc.yaml format")
    indicators = []
    with open(os.path.join(folder, "ioc.yaml")) as f:
        r = yaml.load(f, Loader=yaml.BaseLoader)

    certs = []
    ips = []
    domains = []
    for entry in r:
        if "name" not in entry:
            print("Entry {} without name".format(", ".join(entry.get("names", []))))
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

        # websites
        for ws in entry.get("websites", []):
            if not re.match(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$", ws):
                print("Invalid website {}".format(ws))
                success = False
        c2 = entry.get("c2", {})
        if "ips" in c2:
            for ip in c2["ips"]:
                try:
                    ipp = ipaddress.ip_address(ip)
                except ValueError:
                    print("Invalid IP address : {}".format(ip))
                    success = False
                if ip not in ips:
                    ips.append(ip)
                else:
                    print("Duplicated IP {}".format(ip))
                    success = False

        if "domains" in c2:
            for d in c2["domains"]:
                if not re.match(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$", d):
                    print("Invalid domain format {}".foramt(d))
                    success = False

                if d not in domains:
                    domains.append(d)
                else:
                    print("Duplicated domain {}".format(d))

    return success


def check_samples_format(folder):
    """
    Check format of samples.csv
    """
    success = True
    print("Checking samples.csv format")
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

    return success


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check indicators format")
    parser.add_argument("--folder", "-f", default=".", help="Indicator folder")
    args = parser.parse_args()

    if not os.path.isdir(args.folder):
        print("Invalid folder")
        sys.exit(1)

    success = check_ioc_format(args.folder)
    success &= check_samples_format(args.folder)

    if success:
        print("All good, good work!")
        sys.exit(0)
    else:
        print("Oh noes, there are some issues")
        sys.exit(1)

