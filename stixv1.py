import csv
import re
from stix.core import STIXPackage, STIXHeader
from stix.common import InformationSource, Confidence, StructuredText
from stix.indicator import Indicator as Indicatorv1
from stix.report import Report


def clean_domain(value):
    return re.sub(r'\[\.\]', '.', value)


# STIX v1
def csv_to_stixv1(csv_file):
    stix_package = STIXPackage()

    stix_header = STIXHeader()
    stix_package.stix_header = stix_header
    stix_report = Report()

    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            indicator = row[0]
            description = row[1]
            indicator_item = Indicatorv1()
            indicator_item.title = indicator
            indicator_item.description = StructuredText(value=description)
            print(indicator_item.title)
            print(indicator_item.description)
            #confidence = Confidence(value="Medium")
            #indicator_item.confidence = confidence
            print(indicator_item.confidence)

            stix_package.add_indicator(indicator_item.description)
            # print(stix_package.indicators)
            stix_package.add(stix_report)
            #print(stix_package.to_xml())

    information_source = InformationSource()
    information_source.description = "Securnet"
    stix_package.stix_header.information_source = information_source

    return stix_package


def main():
    csv_file = 'IOCs.csv'

    stix_package = csv_to_stixv1(csv_file)
    # stix1_report = print(stix_package.to_xml())
    with open('output.stix.xml', 'w') as output_file:
        output_file.write(str(stix_package.to_xml(pretty=True)))


if __name__ == "__main__":
    main()