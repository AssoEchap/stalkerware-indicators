import argparse
import os
import sys
import yaml
import hashlib
import yara
from androguard.core.bytecodes.apk import APK
from androguard.core import androconf


def load_indicators(file_path: str) -> dict:
    indicators = {}
    with open(os.path.join(file_path, 'appid.yaml')) as f:
        indicators['appids'] = yaml.load(f, Loader=yaml.BaseLoader)
    with open(os.path.join(file_path, 'certificates.yaml')) as f:
        indicators['certificates'] = yaml.load(f, Loader=yaml.BaseLoader)
    with open(os.path.join(file_path, 'network.csv')) as f:
        data = f.read().split('\n')
        indicators['network'] = []
        for d in data:
            dd = d.strip().split(',')
            if dd[0] in ['domain', 'ip']:
                indicators['network'].append({
                    'type': dd[0],
                    'value': dd[1],
                    'name': dd[2]
                })
    with open(os.path.join(file_path, 'sha256.csv')) as f:
        data = f.read().split('\n')
        indicators['sha256'] = []
        for d in data:
            dd = d.strip().split(',')
            if dd[0] != 'Hash' and len(dd) == 2:
                indicators['sha256'].append({
                    'value': dd[0],
                    'name': dd[1]
                })
    # FixMe : skip if yara is not installed
    indicators['yara'] = yara.compile(os.path.join(file_path, 'rules.yar'))
    return indicators


def search(value: str, db: list, column: str) -> str:
    for d in db:
        if value.lower() == d[column].lower():
            return d['name']
    return None


def check(indicators, path, verbose=False):
    """
    Check an APK with given indicators
    Returns True/False, string (explanation of the discovery)
    """
    m = hashlib.sha256()
    with open(path, 'rb') as f:
        data = f.read()
        m.update(data)
    res = search(m.hexdigest(), indicators['sha256'], 'value')
    if verbose:
        print("SHA256: {}".format(m.hexdigest()))
    if res:
        if verbose:
            print("Known Stalkerware hash: {}".format(res))
            return True, "Known Stalkerware hash: {}".format(res)
    else:
        if verbose:
            print("App hash not in the indicator database")

    apk = APK(path)
    res = search(apk.get_package(), indicators['appids'], 'package')
    if verbose:
        print("Package id: {}".format(apk.get_package()))
    if res:
        if verbose:
            print("Known stalkerware package id: {}".format(res))
        return True, "Known stalkerware package id: {}".format(res)
    else:
        if verbose:
            print("Package id not in the indicators")

    if len(apk.get_certificates()) > 0:
        cert = apk.get_certificates()[0]
        sha1 = cert.sha1_fingerprint.replace(' ', '')
        if verbose:
            print("Certificate: {}".format(sha1))
        res = search(sha1, indicators['certificates'], 'certificate')
        if res:
            if verbose:
                print("Known Stalkerware certificate: {}".format(res))
            return True, "Known Stalkerware certificate: {}".format(res)
        else:
            if verbose:
                print("Certificate not in the indicators")
    else:
        if verbose:
            print("No certificate in this APK")
    if 'yara' in indicators:
        for dex in apk.get_all_dex():
            res = indicators['yara'].match(data=dex)
            if len(res) > 0:
                if verbose:
                    print("Matches yara rules {}".format(res[0]))
                return True, "Yara rule {}".format(res[0])
            else:
                if verbose:
                    print("Does not match any yara rules")
    return False, ""


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check an APK for known malicious indicators')
    parser.add_argument('APK', help='APK file or folder with APKs in it')
    args = parser.parse_args()

    indicator_path = os.path.dirname(os.path.abspath(__file__))
    indicators = load_indicators(indicator_path)

    print("Loaded {} app ids, {} certificates, {} network indicators and {} hashes".format(len(indicators['appids']), len(indicators['certificates']), len(indicators['network']), len(indicators['sha256'])))

    if os.path.isfile(args.APK):
        res, ex = check(indicators, args.APK, verbose=True)
    elif os.path.isdir(args.APK):
        suspicious = []
        for f in os.listdir(args.APK):
            apk_path = os.path.join(args.APK, f)
            if os.path.isfile(apk_path):
                if androconf.is_android(apk_path) == 'APK':
                    res, ex = check(indicators, apk_path)
                    if res:
                        suspicious.append([f, ex])
                        print("{} : identified as {} stalkerware ({})".format(f, "", ex))
                    else:
                        print("{} : OK".format(f))

        print("\n")
        if len(suspicious) == 0:
            print("No suspicious application identified")
        else:
            print("{} suspicious applications identified:".format(len(suspicious)))
            for p in suspicious:
                print("- {} : {}".format(p[0], p[1]))
    else:
        print("This file does not exist")
