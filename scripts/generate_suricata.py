import csv
from datetime import datetime


ioc_from_echap = 'network.csv'
sid_start = 1000000
sid = sid_start
output_rules_file = 'generated/suricata.rules'



def fang(s):
    return s.replace('.', '[.]')



with open(output_rules_file, mode='w') as output:
    with open(ioc_from_echap, newline='') as ioc_list:
        reader = csv.DictReader(ioc_list)
        for ioc in reader:
            ioc_type = ioc.get('Type')
            ioc_indicator = ioc.get('Indicator')
            ioc_app = ioc.get('App')
            if ioc_type == 'domain':
                rule = f'alert dns $HOME_NET any -> any any (msg:"PTS STALKERWARE {ioc_app} ({fang(ioc_indicator)})"; dns.query; content:"{ioc_indicator}"; depth:{len(ioc_indicator)}; nocase; endswith; fast_pattern; reference:url,piroguetoolsuite.github.io/; classtype:targeted-activity; sid:{sid}; rev:1;)\n'
                sid += 1
                output.write(rule)
            if ioc_type == 'ipv4':
                rule = f'alert ip $HOME_NET any -> [{ioc_indicator}] any (msg:"PTS STALKERWARE {ioc_app} ({fang(ioc_indicator)})"; classtype:targeted-activity; sid:{sid}; rev:1;)\n'
                sid += 1
                output.write(rule)

            assert(sid < 1999999)