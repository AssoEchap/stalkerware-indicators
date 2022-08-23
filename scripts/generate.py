import sys
import os
import yaml
import csv
import json
import argparse
from pathlib import Path
from collections import defaultdict
from stix2.v21 import (Indicator, Malware, Relationship, Bundle, DomainName)
from pymisp import MISPEvent


def get_indicators(path):
    with open(os.path.join(path, 'ioc.yaml')) as f:
        r = yaml.load(f, Loader=yaml.BaseLoader)
        data = list(r)

    samples = {}
    with open(os.path.join(path, "samples.csv")) as f:
        reader = csv.reader(f, delimiter=',')
        for row in reader:
            if row[0] == "SHA256":
                continue

            appname = row[4].strip()
            if appname not in samples.keys():
                samples[appname] = []

            samples[appname].append(row[0])

    for d in data:
        d["sha256"] = []
        if d["name"] in samples:
            d["sha256"] += samples[d["name"]]
        if "names" in d:
            for name in d["names"]:
                if name in samples:
                    d["sha256"] += samples[name]

        d["sha256"] = list(set(d["sha256"]))

    return data


def generate_hosts(output, iocs):
    """
    Generate host file
    """
    fpath = os.path.join(output, "hosts")
    if os.path.isfile(fpath):
        os.remove(fpath)

    domains = []
    for app in iocs:
        for d in app.get("c2", {}).get("domains", []):
            domains.append(d)

    with open(fpath, 'w') as f:
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
        for domain in app.get("c2", {}).get("domains", []):
            res['iocs'].append({
                'type': 'domain',
                'tag': 'stalkerware',
                'tlp': 'white',
                'value': domain
            })
        for domain in app.get("websites", []):
            res['iocs'].append({
                'type': 'domain',
                'tag': 'stalkerware',
                'tlp': 'white',
                'value': domain
            })
        for ip in app.get("c2", {}).get("ips", []):
            res["iocs"].append({
                'type': 'ip4addr',
                'tag': 'stalkerware',
                'tlp': 'white',
                'value': ip
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
            for domain in app.get("c2", {}).get("domains", []):
                writer.writerow(["domain", domain, app["name"]])
            for ip in app.get("c2", {}).get("ips", []):
                writer.writerow(["ipv4", ip, app["name"]])

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
    for app in iocs:
        malware = Malware(name=app["name"], is_family=False, description="Stalkerware applications")
        res.append(malware)
        for d in app.get("c2", {}).get("domains", []):
            i = Indicator(indicator_types=["malicious-activity"], pattern="[domain-name:value='{}']".format(d), pattern_type="stix")
            res.append(i)
            res.append(Relationship(i, 'indicates', malware))

        for d in app.get("websites", []):
            i = Indicator(indicator_types=["malicious-activity"], pattern="[domain-name:value='{}']".format(d), pattern_type="stix")
            res.append(i)
            res.append(Relationship(i, 'indicates', malware))

        for h in app.get("sha256", []):
            i = Indicator(indicator_types=["malicious-activity"], pattern="[file:hashes.sha256='{}']".format(h), pattern_type="stix")
            res.append(i)
            res.append(Relationship(i, 'indicates', malware))

        for a in app.get("packages", []):
            i = Indicator(indicator_types=["malicious-activity"], pattern="[app:id='{}']".format(a), pattern_type="stix")
            res.append(i)
            res.append(Relationship(i, 'indicates', malware))

        for c in app.get("certificates", []):
            i = Indicator(indicator_types=["malicious-activity"], pattern="[app:cert.sha1='{}']".format(c), pattern_type="stix")
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
            for d in app.get("c2", {}).get("domains", []):
                output.write('alert dns $HOME_NET any -> any any (msg:"PTS STALKERWARE {} ({})"; dns.query; content:"{}"; depth:{}; nocase; endswith; fast_pattern; reference:url,github.com/AssoEchap/stalkerware-indicators; classtype:targeted-activity; sid:{}; rev:1;)\n'.format(app["name"], fang(d), d, len(d), sid))
                sid += 1
            for ip in app.get("c2", {}).get("ips", []):
                output.write('alert ip $HOME_NET any -> [{}] any (msg:"PTS STALKERWARE {} ({})"; classtype:targeted-activity; sid:{}; rev:1;)\n'.format(ip, fang(ip), app["name"], sid))
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
        event.add_attribute('link', 'https://github.com/AssoEchap/stalkerware-indicators', comment='Source')
        current_iocs = defaultdict(lambda: defaultdict(dict, {k: set() for k in ('domains', 'appids', 'certificates', 'sha256', 'ips')}))

    # make objects
    for app in iocs:
        if app["name"] not in current_iocs:
            o = event.add_object(name='android-app')
            o.add_attribute('name', app["name"])
        else:
            # Find existing object to update
            for obj in event.objects:
                if obj.get_attributes_by_relation('name')[0].value == app["name"]:
                    o = obj
                    break
        o.add_attributes('domain', *list(set(app.get("c2", {}).get("domains", [])) - current_iocs[app["name"]]['domains']))
        # FIXME: add IP
        #o.add_attributes('ip', *list(set([e['indicator'] for e in entries['ips']]) - current_iocs[app_name]['ips']))
        o.add_attributes('sha256', *list(set(app.get('sha256', [])) - current_iocs[app["name"]]['sha256']))
        o.add_attributes('certificate', *list(set(app.get('certificates', [])) - current_iocs[app["name"]]['certificates']))
        o.add_attributes('appid', *list(set(app['packages']) - current_iocs[app["name"]]['appids']))

    with open(fpath, 'w') as f:
        f.write(event.to_json(indent=2))

    print(f"Generated {fpath}")


def update_readme(output, iocs):
    """
    Update the README with an up to date list of stalkerware
    """
    opath = Path(output).parent / 'README.tpl'
    dpath = Path(output).parent / 'README.md'
    if not os.path.isfile(opath):
        print("README.tpl not found")
        return

    with open(opath, "r") as f:
        data = f.read().split("\n")

    os.remove(dpath)
    i = 0
    fout = open(dpath, "w+")
    while data[i] != "## Stalkerware":
        fout.write(data[i] + "\n")
        i += 1

    fout.write("## Stalkerware\n\n")

    nb_samples = sum([len(a["sha256"]) for a in iocs])
    fout.write("This repository includes indicators for {} stalkerware applications ({} samples)\n\n".format(len(iocs), nb_samples))

    for app in sorted(iocs, key=lambda x: x["name"]):
        if len(app["websites"]) > 0:
            fout.write("* {} ({})\n".format(
                app["name"],
                " ".join(["`" + a + "`" for a in app["websites"]])
            ))
        else:
            fout.write("* {}\n".format(app["name"]))

    fout.write("\n")
    while data[i] != "## Notable users":
        i += 1

    while i < len(data):
        fout.write(data[i] + "\n")
        i += 1

    print("README.md updated")


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
    update_readme(args.output, iocs)
