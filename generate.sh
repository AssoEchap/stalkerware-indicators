#! /bin/bash
python scripts/create-indicators-for-tinycheck.py
python scripts/generate_hosts.py
python scripts/generate_stix.py
python scripts/make_misp_event.py
python scripts/generate_suricata.py
