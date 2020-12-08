import json, csv, yaml

DOMAINS_FILE = 'network.csv'
CERTIFICATES_FILE = 'certificates.yaml'

def load_stalkerware_domains():
    domains = []
    try:
        with open(DOMAINS_FILE, 'r') as domains_file:
            csv_contents = csv.reader(domains_file, delimiter=',')
            for line in csv_contents:
                domains.append(line[1])
            return [line[1] in line in csv_contents]
    except Exception:
        print("Error loading {}: {}".format(DOMAINS_FILE, Exception.__format__()))
        return False


def load_stalkerware_certificates():
    try:
        with open(CERTIFICATES_FILE, 'r') as cert_file:
            return yaml.load(cert_file, yaml.SafeLoader)

    except Exception:
        print("Error loading {}: {}".format(DOMAINS_FILE, Exception.__format__()))
        return False

iocs = {'iocs': []}
domains = load_stalkerware_domains()
for domain in domains:
    iocs['iocs'].append({
        'type': 'domain',
        'tag': 'stalkerware',
        'tlp': 'white',
        'value': domain
    })

certificates = load_stalkerware_certificates()
for c in certificates:
    iocs['iocs'].append({
        'type':'sha1cert',
        'tag': 'stalkerware',
        'tlp': 'white',
        'value': c['certificate']
    })

with open('indicators-for-tinycheck.json', 'w') as f:
    f.write(json.dumps(iocs))


