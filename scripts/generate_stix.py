import sys
import os
import yaml
import csv
from collections import defaultdict
from stix2.v21 import (Indicator, Malware, Relationship, Bundle, DomainName)


if __name__ == "__main__":
    if os.path.isfile("stalkerware.stix2"):
        os.remove("stalkerware.stix2")

    indicators_by_name = defaultdict(lambda: defaultdict(dict, {k: set() for k in ('domains', 'appids', 'certificates', 'sha256')}))

    with open('network.csv') as f:
        r = csv.DictReader(f)
        for row in r:
            app = row['App'].lower()
            if row['Type'] == "domain":
                indicators_by_name[app]['domains'].add(row['Indicator'])

    with open('sha256.csv') as f:
        r = csv.DictReader(f)
        for row in r:
            app = row['App'].lower()
            indicators_by_name[app]['sha256'].add(row['Hash'])

    with open('certificates.yaml') as f:
        r = yaml.load(f, Loader=yaml.BaseLoader)
        for entry in r:
            app = entry['name'].lower()
            indicators_by_name[app]['certificates'].add(entry['certificate'])

    with open('appid.yaml') as f:
        r = yaml.load(f, Loader=yaml.BaseLoader)
        for entry in r:
            app = entry['name'].lower()
            indicators_by_name[app]['appids'].add(entry['package'])


    res = []
    for app_name, entries in indicators_by_name.items():
        malware = Malware(name=app_name, is_family=False, description="Stalkerware applications")
        res.append(malware)
        for d in entries['domains']:
            i = Indicator(indicator_types=["malicious-activity"], pattern="[domain-name:value='{}']".format(d), pattern_type="stix")
            res.append(i)
            res.append(Relationship(i, 'indicates', malware))

        for h in entries['sha256']:
            i = Indicator(indicator_types=["malicious-activity"], pattern="[file:hashes.sha256='{}']".format(h), pattern_type="stix")
            res.append(i)
            res.append(Relationship(i, 'indicates', malware))

        for a in entries['appids']:
            i = Indicator(indicator_types=["malicious-activity"], pattern="[app:id='{}']".format(a), pattern_type="stix")
            res.append(i)
            res.append(Relationship(i, 'indicates', malware))

        for c in entries['certificates']:
            i = Indicator(indicator_types=["malicious-activity"], pattern="[app:cert.md5='{}']".format(c), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    bundle = Bundle(objects=res)
    with open("stalkerware.stix2", "w+") as f:
        f.write(str(bundle))
    print("stalkerware.stix2 file created")
