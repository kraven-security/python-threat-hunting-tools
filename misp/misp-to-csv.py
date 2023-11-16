import csv
from pymisp import PyMISP
from config import config


field_names = ["type", "value"]

# create CSV to write IOCs to
with open('iocs.csv', mode='w', newline='') as file:
    # create a csv writer object
    writer = csv.DictWriter(file, fieldnames=field_names)

    # add a header row 
    writer.writeheader()


    # get all IOCs with IDS flag set to true
    attributes = misp.search(controller='attributes', to_ids=1, pythonify=True)

    # write IOCs to csv file
    for row in attributes:
        # create a new dictionary with only IOC value and type 
        selected_row = {key: row[key] for key in field_names}
        # try to write IOC to CSV file, if failed then continue to next IOC
        try:
            writer.writerow(selected_row)
        except UnicodeDecodeError:
            continue
