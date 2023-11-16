import csv
import argparse

# get csv file from command line using argparse
parser = argparse.ArgumentParser()
parser.add_argument("csv_file", help="CSV file (needs to be in same directory)")
args = parser.parse_args()


# open csv file 
csv_file = args.csv_file
with open(csv_file, 'r') as file:
    # create CSV reader object
    reader = csv.reader(file)

    # create a list to critical vulns (9+ cvss)
    critical_vulns = [] 

    # loop through rows
    for row in reader:

        # skip header row 
        if row[4] == "CVSS":
            critical_vulns.append(row)
            continue

        # check cvss score
        if float(row[4]) >= 9.0:
            critical_vulns.append(row)


# create new CSV file containing only critical critical 
filename = '[CRITICAL] ' + csv_file 
with open(filename, 'w', newline='') as file:
    # create CSV writer object 
    writer = csv.writer(file)

    # write critical vulns to file 
    writer.writerows(critical_vulns)


print(f"Finished writing {len(critical_vulns) - 1} to {filename}")
