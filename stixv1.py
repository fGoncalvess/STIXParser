import re
import os
import csv
from enum import Enum
from stix.core import STIXPackage
from stix.indicator import Indicator
from stix.ttp import TTP, Behavior
from stix.ttp.behavior import MalwareInstance
from cybox.objects.uri_object import URI
from cybox.objects.address_object import Address
from cybox.objects.file_object import File
from cybox.common import Hash

def clean_domain(value):
    return re.sub(r'\[\.\]', '.', value)

def is_ip_address(value):
    ip_regex = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    return bool(ip_regex.match(value))

def is_url(value):
    url_regex = re.compile(r'.*\.com')
    return bool(url_regex.match(value))

def csv_to_stix(csv_file):
    print(f"CSV File Path: {csv_file}")

    if not os.path.isfile(csv_file):
        print("Not Found")
        return

    with open(csv_file, 'r') as data:
        reader = csv.reader(data)
        stixPackage = STIXPackage()
        for row in reader:
            print(f"Processing Row: {row}")
            value = clean_domain(row[0])

            #IP Address
            if is_ip_address(value):
                ttp = TTP(title="C2 Behavior")

                indicator = Indicator(title="IP Address for known C2 Channel")
                indicator.add_indicator_type("IP Watchlist")

                addr = Address(address_value=value, category=Address.CAT_IPV4)
                addr.condition = "Equals"
                indicator.add_observable(addr)
                indicator.add_indicated_ttp(TTP(idref=ttp.id_))

                stixPackage.add_indicator(indicator)
                stixPackage.add_ttp(ttp)

            #URL
            elif is_url(value):
                indicator = Indicator(title="Domain known for Malicious Action")
                indicator.add_indicator_type("URL Watchlist")

                url = URI()
                url.value = value
                url.type = URI.TYPE_URL
                url.condition = "Equals"

                indicator.add_observable(url)

                stixPackage.add_indicator(indicator)

            #File Hash
            else:
                malware_instance = MalwareInstance()
                malware_instance.add_name("Unknown")
                malware_instance.add_type("Bot")

                ttp = TTP(title="Unknown")
                ttp.behavior = Behavior()
                ttp.behavior.add_malware_instance(malware_instance)

                file_object = File()
                file_object.add_hash(Hash(value))
                file_object.hashes[0].simple_hash_value.condition = "Equals"

                indicator = Indicator(title="File Hash Unknown")
                indicator.add_indicator_type("File Hash Watchlist")
                indicator.add_observable(file_object)
                indicator.add_indicated_ttp(TTP(idref=ttp.id_))

                stixPackage.add_indicator(indicator)
                stixPackage.add_ttp(ttp)

    output_file = 'outputV1.xml'
    with open(output_file, 'w') as output:
        output.write(stixPackage.to_xml(encoding=None))

if __name__ == '__main__':
    csv_file = os.path.abspath("IOCs.csv")
    csv_to_stix(csv_file)