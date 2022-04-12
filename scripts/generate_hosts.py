import json, csv, os

NETWORK_FILE = 'network.csv'
FPATH = "generated/hosts"

def get_stalkerware_domains():
    with open(NETWORK_FILE, 'r') as f:
        csv_contents = list(csv.reader(f, delimiter=','))
        domains = [line[1] for line in csv_contents if line[0].strip() == "domain"]
        ips = [line[1] for line in csv_contents if line[0].strip() == "ipv4"]
        return domains, ips


if os.path.isfile(FPATH):
    os.remove(FPATH)

domains, ips = get_stalkerware_domains()

with open(FPATH, 'w') as f:
    for d in domains:
        f.write("{}\n".format(d))
