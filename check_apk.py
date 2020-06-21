import argparse
import os
import sys
import yaml
import hashlib
from androguard.core.bytecodes.apk import APK


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

    return indicators


def search(value: str, db: list, column: str) -> str:
    for d in db:
        if value.lower() == d[column].lower():
            return d['name']
    return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check an APK for known malicious indicators')
    parser.add_argument('APK', help='APK File')
    args = parser.parse_args()

    if not os.path.isfile(args.APK):
        print("This file does not exist")
        sys.exit(-1)

    indicator_path = os.path.dirname(os.path.abspath(__file__))
    indicators = load_indicators(indicator_path)

    print("Checking this APK over {} app ids, {} certificates, {} network indicators and {} hashes".format(len(indicators['appids']), len(indicators['certificates']), len(indicators['network']), len(indicators['sha256'])))

    # TODO implement check for a folder

    # Checking hash
    m = hashlib.sha256()
    with open(args.APK, 'rb') as f:
        data = f.read()
        m.update(data)
    res = search(m.hexdigest(), indicators['sha256'], 'value')
    print("SHA256: {}".format(m.hexdigest()))
    if res:
        print("Known Stalkerware hash: {}".format(res))
    else:
        print("App hash not in the indicator database")

    print("")

    apk = APK(args.APK)
    res = search(apk.get_package(), indicators['appids'], 'package')
    print("Package id: {}".format(apk.get_package()))
    if res:
        print("Known stalkerware package id: {}".format(res))
    else:
        print("Package id not in the indicators")

    print("")

    if len(apk.get_certificates()) > 0:
        cert = apk.get_certificates()[0]
        sha1 = cert.sha1_fingerprint.replace(' ', '')
        print("Certificate: {}".format(sha1))
        res = search(sha1, indicators['certificates'], 'certificate')
        if res:
            print("Known Stalkerware certificate: {}".format(res))
        else:
            print("Certificate not in the indicators")
    else:
        print("No certificate in this APK")

    # TODO : add rules and androguard rules
