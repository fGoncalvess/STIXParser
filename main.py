import csv
import re
from stix2 import Indicator, Bundle, MemoryStore

def is_ip_address(value):
    ip_regex = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    return bool(ip_regex.match(value))

def clean_domain(value):
    return re.sub(r'\[\.\]', '.', value)

# STIX v2
def csv_to_stix(csv_file):
    stix_objects = []

    with open (csv_file, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            ip_or_domain = clean_domain(row[0])
            action = row[1]

            if is_ip_address(ip_or_domain):
                pattern = "[ipv4-addr:value = '{}']".format(ip_or_domain)
                description = "Este endereço de IP esta potencialmente associado a atividades maliciosas e listado em diversas BlackLists."
            else:
                pattern = "[url:value = '{}']".format(ip_or_domain)
                description = "Este URL esta potencialmente associado a ativadades maliciosas e listado em diversas BlackLists."
            indicator = Indicator(
                pattern=pattern,
                description=description,
                pattern_type="stix",
                name="Malicious Activity",
            )

            stix_objects.append(indicator)
    bundle = Bundle(objects=stix_objects)
    return bundle

def main():
    csv_file = 'IOCs.csv'
    stix_bundle = csv_to_stix(csv_file)
    with open('output.xml', 'w') as output_file:
        output_file.write(stix_bundle.serialize(pretty=True))

if __name__ == "__main__":
    main()