import argparse
import os
import sys
import yaml
import hashlib
import yara
import csv
from pathlib import Path
from androguard.core.bytecodes.apk import APK
from androguard.core import androconf


def search(value: str, db: dict, getter: type) -> str:
    for app in db:
        for d in getter(app):
            if value.lower() == d.lower():
                return app["name"]
    return None


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


def check(iocs, rules, path, verbose=False):
    """
    Check an APK with given indicators
    Returns True/False, string (explanation of the discovery)
    """
    stalkerware = False
    stalkerware_app = ""
    m = hashlib.sha256()
    with open(path, 'rb') as f:
        data = f.read()
        m.update(data)
    res = search(m.hexdigest(), iocs, lambda x: x.get("sha256", []))
    if verbose:
        print("SHA256: {}".format(m.hexdigest()))
    if res:
        if verbose:
            print("Known Stalkerware hash for {}".format(res))
            stalkerware = True
            stalkerware_app = res
    else:
        if verbose:
            print("App hash not in the indicator database")

    apk = APK(path)
    res = search(apk.get_package(), iocs, lambda x: x.get("packages", []))
    if verbose:
        print("Package id: {}".format(apk.get_package()))
    if res:
        if verbose:
            print("Known stalkerware package id for {}".format(res))
        stalkerware = True
        stalkerware_app = res
    else:
        if verbose:
            print("Package id not in the indicators")

    if len(apk.get_certificates()) > 0:
        cert = apk.get_certificates()[0]
        sha1 = cert.sha1_fingerprint.replace(' ', '')
        if verbose:
            print("Certificate: {}".format(sha1))
        res = search(sha1, iocs, lambda x: x.get("certificates", []))
        if res:
            if verbose:
                print("Known Stalkerware certificate for {}".format(res))
                stalkerware = True
                stalkerware_app = res
        else:
            if verbose:
                print("Certificate not in the indicators")
    else:
        if verbose:
            print("No certificate in this APK")

    if rules:
        for dex in apk.get_all_dex():
            res = rules.match(data=dex)
            if len(res) > 0:
                if verbose:
                    print("Matches yara rules {}".format(res[0]))
                stalkerware = True
                stalkerware_app = res[0]
            else:
                if verbose:
                    print("Does not match any yara rules")
    return stalkerware, stalkerware_app


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check an APK for known malicious indicators')
    parser.add_argument('--iocs', '-i', help='Path to IOC filder (containing iocs.yaml and samples.csv)')
    parser.add_argument('--yara', '-y', help='Path to yara rules')
    parser.add_argument('APK', help='APK file or folder with APKs in it')
    args = parser.parse_args()

    if args.iocs:
        indicators = get_indicators(args.iocs)
    else:
        indicator_path = Path(__file__).parent.parent.absolute()
        if os.path.isdir(indicator_path):
            indicators = get_indicators(indicator_path)
        else:
            print("Please provide yaml IOC file with --iocs")
            sys.exit(1)

    if args.yara:
        rules = yara.compile(args.yara)
    else:
        indicator_path = Path(__file__).parent.parent.absolute()
        yara_path = os.path.join(indicator_path, 'rules.yar')
        if os.path.isfile(yara_path):
            rules = yara.compile(yara_path)
        else:
            print("No yara rules provided")

    print("Loaded indicators for {} apps".format(len(indicators)))

    if os.path.isfile(args.APK):
        res, _ = check(indicators, rules, args.APK, verbose=True)
    elif os.path.isdir(args.APK):
        suspicious = []
        for f in os.listdir(args.APK):
            apk_path = os.path.join(args.APK, f)
            if os.path.isfile(apk_path):
                if androconf.is_android(apk_path) == 'APK':
                    res, app = check(indicators, rules, apk_path)
                    if res:
                        suspicious.append(f)
                        print("{} : identified as {} stalkerware".format(f, app))
                    else:
                        print("{} : OK".format(f))

        print("\n")
        if len(suspicious) == 0:
            print("No suspicious application identified")
        else:
            print("{} suspicious applications identified:".format(len(suspicious)))
            for p in suspicious:
                print("- {}".format(p))
    else:
        print("This file does not exist")
