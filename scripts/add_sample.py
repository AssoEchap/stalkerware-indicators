import argparse
import os
import sys
import hashlib
import csv
from pathlib import Path
from generate import get_indicators
from androguard.core.bytecodes.apk import APK
from androguard.core import androconf


def get_infos(path):
    m = hashlib.sha256()
    with open(path, 'rb') as f:
        data = f.read()
        m.update(data)
    sha256 = m.hexdigest()
    apk = APK(path)

    if len(apk.get_certificates()) > 0:
        cert = apk.get_certificates()[0]
        cert_sha1 = cert.sha1_fingerprint.replace(' ', '')
    else:
        cert_sha1 = ""

    return {"sha256": sha256, "package": apk.get_package(), "cert": cert_sha1, "version": apk.get_androidversion_code()}


def read_samples(path):
    data = []
    with open(path) as f:
        reader = csv.reader(f, delimiter=',')
        for row in reader:
            if row[0] == "SHA256":
                continue
            data.append(row)

    return data


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Add an APK to the list of samples')
    parser.add_argument("APK", help="APK file")
    parser.add_argument("NAME", help="App name")
    args = parser.parse_args()

    sample_path = os.path.join(Path(__file__).parent.parent.absolute(), "samples.csv")

    if not os.path.isfile(args.APK):
        print("Invalid file")
        sys.exit(-1)

    if androconf.is_android(args.APK) != "APK":
        print("This file is not an APK")
        sys.exit(-1)

    print(sample_path)
    infos = get_infos(args.APK)
    data = read_samples(sample_path)

    os.remove(sample_path)
    with open(sample_path, "w+") as f:
        writer = csv.writer(f, delimiter=',')
        writer.writerow(["SHA256", "Package Name", "Certificate", "Version", "App"])

        found = False
        for d in data:
            if d[0].lower() == infos["sha256"].lower():
                writer.writerow([
                    d[0].lower(),
                    infos["package"],
                    infos["cert"],
                    infos["version"],
                    args.NAME
                ])
                found = True
                print("Updated the entry")
            else:
                writer.writerow(d)

        if not found:
            writer.writerow([
                infos["sha256"].lower(),
                infos["package"],
                infos["cert"],
                infos["version"],
                args.NAME
            ])
            print("Added to the list")
