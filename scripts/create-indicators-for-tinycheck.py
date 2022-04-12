import json, csv, os

NETWORK_FILE = 'network.csv'
FPATH = "generated/indicators-for-tinycheck.json"

def load_stalkerware_domains():
    with open(NETWORK_FILE, 'r') as f:
        csv_contents = list(csv.reader(f, delimiter=','))
        domains = [line[1] for line in csv_contents if line[0].strip() == "domain"]
        ips = [line[1] for line in csv_contents if line[0].strip() == "ipv4"]
        return domains, ips


iocs = {'iocs': []}
domains, ips = load_stalkerware_domains()
if domains:
    for domain in domains:
        iocs['iocs'].append({
            'type': 'domain',
            'tag': 'stalkerware',
            'tlp': 'white',
            'value': domain
        })
if ips:
    for ip in ips:
        iocs['iocs'].append({
            'type': 'ip4addr',
            'tag': 'stalkerware',
            'tlp': 'white',
            'value': ip
        })

if os.path.isfile(FPATH):
    os.remove(FPATH)

with open(FPATH, 'w') as f:
    f.write(json.dumps(iocs))
