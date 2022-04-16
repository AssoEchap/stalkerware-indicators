import sys
import os
import yaml
import csv
import json
import argparse
from collections import defaultdict
from stix2.v21 import (Indicator, Malware, Relationship, Bundle, DomainName)
from pymisp import MISPEvent


def get_indicators(path):
    iocs_by_app = defaultdict(lambda: defaultdict(dict, {k: list() for k in ('domains', 'appids', 'certificates', 'sha256', 'ips')}))

    with open(os.path.join(path, 'network.yaml')) as f:
        r = yaml.load(f, Loader=yaml.BaseLoader)
        for entry in r:
            app = entry['app'].lower()
            if entry['type'] == "domain":
                iocs_by_app[app]['domains'].append({"indicator": entry['indicator'], "tags": entry.get("tags", [])})
            else:
                iocs_by_app[app]['ips'].append({"indicator": entry['indicator'], "tags": entry.get("tags", [])})

    with open(os.path.join(path, "certificates.yaml")) as f:
        r = yaml.load(f, Loader=yaml.BaseLoader)
        for entry in r:
            app = entry['name'].lower()
            iocs_by_app[app]['certificates'].append(entry['certificate'])

    with open('sha256.csv') as f:
        r = csv.DictReader(f)
        for row in r:
            app = row['App'].lower()
            iocs_by_app[app]['sha256'].append(row['Hash'])

    with open('certificates.yaml') as f:
        r = yaml.load(f, Loader=yaml.BaseLoader)
        for entry in r:
            app = entry['name'].lower()
            iocs_by_app[app]['certificates'].append(entry['certificate'])

    with open('appid.yaml') as f:
        r = yaml.load(f, Loader=yaml.BaseLoader)
        for entry in r:
            app = entry['name'].lower()
            iocs_by_app[app]['appids'].append(entry['package'])

    return iocs_by_app


def generate_hosts(output, iocs):
    """
    Generate host file
    """
    fpath = os.path.join(output, "hosts")
    if os.path.isfile(fpath):
        os.remove(fpath)

    with open(fpath, 'w') as f:
        domains = [b['indicator'] for a in iocs for b in iocs[a]["domains"] if "c2" in b["tags"]]
        for d in sorted(domains):
            f.write("{}\n".format(d))
    print(f"Generated {fpath}")


def generate_tinycheck(output, iocs):
    """
    Generate tinycheck IOC format
    """
    fpath = os.path.join(output, "indicators-for-tinycheck.json")
    if os.path.isfile(fpath):
        os.remove(fpath)

    res = {'iocs': []}
    for app in iocs:
        for domain in iocs[app]["domains"]:
            res['iocs'].append({
                'type': 'domain',
                'tag': 'stalkerware',
                'tlp': 'white',
                'value': domain["indicator"]
            })
        for ip in iocs[app]["ips"]:
            res["iocs"].append({
                'type': 'ip4addr',
                'tag': 'stalkerware',
                'tlp': 'white',
                'value': ip["indicator"]
            })

    with open(fpath, 'w') as f:
        f.write(json.dumps(res))

    print(f"Generated {fpath}")


def generate_network_csv(output, iocs):
    """
    generate network.csv file
    """
    fpath = os.path.join(output, "network.csv")
    if os.path.isfile(fpath):
        os.remove(fpath)

    with open(fpath, "w") as csvfile:
        writer = csv.writer(csvfile,)
        writer.writerow(["type", "indicator", "app"])
        for app in iocs:
            for domain in iocs[app]["domains"]:
                writer.writerow(["domain", domain["indicator"], app])
            for ip in iocs[app]["ips"]:
                writer.writerow(["ipv4", ip["indicator"], app])

    print(f"Generated {fpath}")


def generate_stix(folder, iocs):
    """
    Generate STIX file
    FIXME: add IPs
    """
    fpath = os.path.join(folder, "stalkerware.stix2")
    if os.path.isfile(fpath):
        os.remove(fpath)

    res = []
    for app_name, entries in iocs.items():
        malware = Malware(name=app_name, is_family=False, description="Stalkerware applications")
        res.append(malware)
        for d in entries['domains']:
            i = Indicator(indicator_types=["malicious-activity"], pattern="[domain-name:value='{}']".format(d["indicator"]), pattern_type="stix")
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
    with open(fpath, "w+", encoding="utf-8") as f:
        f.write(str(bundle))

    print(f"Generated {fpath}")


def generate_suricata(folder, iocs):
    """
    Generate suricate file
    """
    def fang(s):
        return s.replace('.', '[.]')
    sid = 1000000
    fpath = os.path.join(folder, "suricata.rules")
    if os.path.isfile(fpath):
        os.remove(fpath)

    with open(fpath, mode='w') as output:
        for app in iocs:
            for d in iocs[app]["domains"]:
                output.write('alert dns $HOME_NET any -> any any (msg:"PTS STALKERWARE {} ({})"; dns.query; content:"{}"; depth:{}; nocase; endswith; fast_pattern; classtype:targeted-activity; sid:{}; rev:1;)\n'.format(app, fang(d["indicator"]), d["indicator"], len(d["indicator"]), sid))
                sid += 1
            for ip in iocs[app]["ips"]:
                output.write('alert ip $HOME_NET any -> [{}] any (msg:"PTS STALKERWARE {} ({})"; classtype:targeted-activity; sid:{}; rev:1;)\n'.format(ip["indicator"], fang(ip["indicator"]), app, sid))
                sid += 1

    print(f"Generated {fpath}")


def load_mispevent(mispevent):
    current_indicators_by_name = defaultdict(lambda: defaultdict(dict, {k: set() for k in ('domains', 'appids', 'certificates', 'sha256', 'ips')}))
    for obj in mispevent.objects:
        appname = obj.get_attributes_by_relation('name')[0].value
        sha256 = obj.get_attributes_by_relation('sha256')
        for s in sha256:
            current_indicators_by_name[appname]['sha256'].add(s.value)
        domains = obj.get_attributes_by_relation('domain')
        for domain in domains:
            current_indicators_by_name[appname]['domains'].add(domain.value)
        #ips = obj.get_attributes_by_relation('ip-dst')
        #for ip in ips:
            #current_indicators_by_name[appname]['ips'].add(ip.value)
        appids = obj.get_attributes_by_relation('appid')
        for appid in appids:
            current_indicators_by_name[appname]['appids'].add(appid.value)
        certificates = obj.get_attributes_by_relation('certificate')
        for cert in certificates:
            current_indicators_by_name[appname]['certificates'].add(cert.value)
    return current_indicators_by_name


def generate_misp(folder, iocs):
    """
    Generate MISP file
    """
    fpath = os.path.join(folder, "misp_event.json")
    if os.path.isfile(fpath):
        event = MISPEvent()
        event.load_file(fpath)
        current_iocs = load_mispevent(event)
    else:
        event = MISPEvent()
        event.info = 'Stalkerware indicators'
        event.distribution = 3
        event.publish()
        event.add_attribute('link', 'https://github.com/Te-k/stalkerware-indicators', comment='Source')
        current_iocs = defaultdict(lambda: defaultdict(dict, {k: set() for k in ('domains', 'appids', 'certificates', 'sha256', 'ips')}))

    # make objects
    for app_name, entries in iocs.items():
        if app_name not in current_iocs:
            o = event.add_object(name='android-app')
            o.add_attribute('name', app_name)
        else:
            # Find existing object to update
            for obj in event.objects:
                if obj.get_attributes_by_relation('name')[0].value == app_name:
                    o = obj
                    break
        o.add_attributes('domain', *list(set([e['indicator'] for e in entries['domains']]) - current_iocs[app_name]['domains']))
        # FIXME: add IP
        #o.add_attributes('ip', *list(set([e['indicator'] for e in entries['ips']]) - current_iocs[app_name]['ips']))
        o.add_attributes('sha256', *list(set(entries['sha256']) - current_iocs[app_name]['sha256']))
        o.add_attributes('certificate', *list(set(entries['certificates']) - current_iocs[app_name]['certificates']))
        o.add_attributes('appid', *list(set(entries['appids']) - current_iocs[app_name]['appids']))

    with open(fpath, 'w') as f:
        f.write(event.to_json(indent=2))

    print(f"Generated {fpath}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate several IOC format for stalkerware")
    parser.add_argument("--input", "-i", default=".", help="Folder with stalkerware IOCs")
    parser.add_argument("--output", "-o", default="generated", help="output folder")
    args = parser.parse_args()

    # Read all indicators
    iocs = get_indicators(args.input)

    generate_hosts(args.output, iocs)
    generate_tinycheck(args.output, iocs)
    generate_network_csv(args.output, iocs)
    generate_stix(args.output, iocs)
    generate_suricata(args.output, iocs)
    generate_misp(args.output, iocs)
