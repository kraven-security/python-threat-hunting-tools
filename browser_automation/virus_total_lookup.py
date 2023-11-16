from selenium.webdriver.edge.service import Service as EdgeService
from selenium.webdriver.edge.options import Options
from selenium import webdriver
import validators
import os


# loads IOCs from text file to Python list for processing
def load_iocs(filename):
    # create list to store IOCs
    iocs = []
    # open file in read mode
    with open(filename, "r") as f:
        for line in f.readlines():
            iocs.append(line.strip())
    # print output
    print(f"[+] Loaded {len(iocs)} IOCs for testing.")
    # return list of IOCs
    return iocs


# runs IOC list through virus total lookups
def run(iocs):
    # creater web driver to run virus total lookups
    # service = EdgeService(verbose = True)
    service = EdgeService()
    edge_options = Options()
    edge_options.add_experimental_option("detach", True)
    driver = webdriver.Edge(service=service, options=edge_options)

    # keep track of script execution
    count = 1
    print("[+] Starting...")

    for ioc in iocs:
        print(f"{count}/{len(iocs)}")

        # add a new tab to browser window
        driver.switch_to.new_window("tab")

        # filter based on IOC IP address, hash, and domain to query correct URL
        if validators.ip_address.ipv4(ioc):
            driver.get(f"https://www.virustotal.com/gui/ip-address/{ioc}")
        elif validators.domain(ioc):
            driver.get(f"https://www.virustotal.com/gui/domain/{ioc}")
        elif len(ioc) == 32:
            # MD5 hash
            driver.get(f"https://www.virustotal.com/gui/file/{ioc}")
        elif len(ioc) == 40:
            # SHA1 hash
            driver.get(f"https://www.virustotal.com/gui/file/{ioc}")
        elif len(ioc) == 64:
            # SHA256 hash
            driver.get(f"https://www.virustotal.com/gui/file/{ioc}")
        else:
            print(f"[+] Error processing {ioc} ... skipping #{count}")

        # wait to not overload website
        driver.implicitly_wait(5)
        # increase count by 1
        count += 1

    # output finished
    print(f"=== All {len(iocs)} have now ran. You can now analyse. ===")


# get ioc list filename
BASE_DIR = os.getcwd()
FILENAME = os.path.join(BASE_DIR, "iocs.txt")

# gather iocs from file
ioc_list = load_iocs(FILENAME)
# run virus total lookup using iocs
run(ioc_list)
