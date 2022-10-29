import argparse
import os
import sys
import yaml
import hashlib
import yara
from pathlib import Path
from generate import get_indicators
from androguard.core.bytecodes.apk import APK
from androguard.core import androconf


def search(value: str, db: dict, getter: type) -> str:
    for app in db:
        for d in getter(app):
            if value.lower() == d.lower():
                return app["name"]
    return None


def check(iocs, rules, path, verbose=False):
    """
    Check an APK with given indicators
    Returns True/False, string (explanation of the discovery)
    """
    stalkerware = False
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
            else:
                if verbose:
                    print("Does not match any yara rules")
    return stalkerware


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check an APK for known malicious indicators')
    parser.add_argument('APK', help='APK file or folder with APKs in it')
    args = parser.parse_args()

    indicator_path = Path(__file__).parent.parent.absolute()
    indicators = get_indicators(indicator_path)

    rules = yara.compile(os.path.join(indicator_path, 'rules.yar'))
    print("Loaded indicators for {} apps".format(len(indicators)))

    if os.path.isfile(args.APK):
        res = check(indicators, rules, args.APK, verbose=True)
    elif os.path.isdir(args.APK):
        suspicious = []
        for f in os.listdir(args.APK):
            apk_path = os.path.join(args.APK, f)
            if os.path.isfile(apk_path):
                if androconf.is_android(apk_path) == 'APK':
                    res = check(indicators, rules, apk_path)
                    if res:
                        suspicious.append(f)
                        print("{} : identified as {} stalkerware ({})".format(f, "", ex))
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
