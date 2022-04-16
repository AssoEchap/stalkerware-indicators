import yaml
import argparse
import os
import sys
import re


def check_network_format(folder):
    """
    Check format of network.yaml file
    """
    # TODO : test domain / ip format
    success = True
    print("Checking network.yaml format")
    indicators = []
    with open(os.path.join(folder, "network.yaml")) as f:
        r = yaml.load(f, Loader=yaml.BaseLoader)
        for entry in r:
            if "indicator" not in entry:
                print("Entry {} without indicator".format(entry.get("app", "")))
                success = False
            else:
                if entry["indicator"] in indicators:
                    print("Duplicated entry {}".format(entry["indicator"]))
                    success = False
                indicators.append(entry["indicator"])

                if entry.get("type", "") == "ipv4":
                    if not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", entry["indicator"]):
                        # Invalid format
                        print("Invalid IPv4 address {}".format(entry["indicator"]))
                        success = False
                elif entry.get("type", "") == "domain":
                    if not re.match(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$", entry["indicator"]):
                        print("Invalid domain {}".format(entry["indicator"]))
                        success = False

            if "app" not in entry:
                print("Entry {} without app name".format(entry.get("indicator", "")))
                success = False
            if "type" not in entry:
                print("Entry {} without type".format(entry.get("indicator", "")))
                success = False
            else:
                if entry["type"] not in ["domain", "ipv4"]:
                    print("Invalid type {} for indicator {}".format(entry["type"], entry.get("indicator", "")))
                    success = False
            if "tags" not in entry:
                print("Entry {} without tags".format(entry.get("indicator", "")))
                success = False
            else:
                if not isinstance(entry["tags"], list):
                    print("Wrong tags format for indicator {}".format(entry.get("indicators", "")))
                    success = False
                else:
                    for tag in entry["tags"]:
                        if tag not in ["c2", "website", "victim_download"]:
                            print("Invalid tag {} for indicator {}".format(tag, entry.get("indicator", "")))
                            success = False


    return success


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check indicators format")
    parser.add_argument("--folder", "-f", default=".", help="Indicator folder")
    args = parser.parse_args()

    if not os.path.isdir(args.folder):
        print("Invalid folder")
        sys.exit(1)

    success = check_network_format(args.folder)

    if success:
        print("All good, good work!")
        sys.exit(0)
    else:
        print("Oh noes, there are some issues")
        sys.exit(1)

