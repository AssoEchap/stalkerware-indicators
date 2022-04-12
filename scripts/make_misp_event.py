#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import csv
from collections import defaultdict

import yaml

from pymisp import MISPEvent

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


def load_mispevent(mispevent):
    for obj in mispevent.objects:
        appname = obj.get_attributes_by_relation('name')[0].value
        sha256 = obj.get_attributes_by_relation('sha256')
        for s in sha256:
            current_indicators_by_name[appname]['sha256'].add(s.value)
        domains = obj.get_attributes_by_relation('domain')
        for domain in domains:
            current_indicators_by_name[appname]['domains'].add(domain.value)
        appids = obj.get_attributes_by_relation('appid')
        for appid in appids:
            current_indicators_by_name[appname]['appids'].add(appid.value)
        certificates = obj.get_attributes_by_relation('certificate')
        for cert in certificates:
            current_indicators_by_name[appname]['certificates'].add(cert.value)
    return current_indicators_by_name


FPATH = "generated/misp_event.json"
current_indicators_by_name = defaultdict(lambda: defaultdict(dict, {k: set() for k in ('domains', 'appids', 'certificates', 'sha256')}))
if Path(FPATH).exists():
    event = MISPEvent()
    event.load_file(Path(FPATH))
    current_indicators_by_name = load_mispevent(event)
else:
    event = MISPEvent()
    event.info = 'Stalkerware indicators'
    event.distribution = 3
    event.publish()
    event.add_attribute('link', 'https://github.com/Te-k/stalkerware-indicators', comment='Source')

# make objects
for app_name, entries in indicators_by_name.items():
    if app_name not in current_indicators_by_name:
        o = event.add_object(name='android-app')
        o.add_attribute('name', app_name)
    else:
        # Find existing object to update
        for obj in event.objects:
            if obj.get_attributes_by_relation('name')[0].value == app_name:
                o = obj
                break
    o.add_attributes('domain', *list(entries['domains'] - current_indicators_by_name[app_name]['domains']))
    o.add_attributes('sha256', *list(entries['sha256'] - current_indicators_by_name[app_name]['sha256']))
    o.add_attributes('certificate', *list(entries['certificates'] - current_indicators_by_name[app_name]['certificates']))
    o.add_attributes('appid', *list(entries['appids'] - current_indicators_by_name[app_name]['appids']))

with open(FPATH, 'w') as f:
    f.write(event.to_json(indent=2))
