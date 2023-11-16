# script to verify IOCs before adding to MISP
import vt
import validators
import base64
import sys
import nest_asyncio
from config import config
from config import Colors, TextFormat
from time import sleep

# create VT client to run queries
VT_API_KEY = config.VT_API_KEY
MALICIOUS_THRESHOLD = 1
SUSPICIOUS_THRESHOLD = 1
client = vt.Client(VT_API_KEY)

# text formating
BOLD = TextFormat.BOLD
ENDC = Colors.ENDC
RED = Colors.RED
YELLOW = Colors.YELLOW


def ioc_type_check(ioc):
    # check what type an IOC is using validators module and return as string
    if validators.ipv4(ioc) or validators.ipv6(ioc):
        return "ip"
    elif validators.domain(ioc):
        return "domain"
    elif validators.url(ioc):
        return "url"
    elif validators.sha1(ioc) or validators.md5(ioc) or validators.sha256(ioc):
        return "file_hash"

    # return error
    return False


def query_vt(ioc, ioc_type, client):
    # check IOC type and query respective VT endpoint
    try:
        if ioc_type == "ip":
            ip_obj = client.get_object("/ip_addresses/{}", ioc)
            return ip_obj
        elif ioc_type == "domain":
            domain_obj = client.get_object("/domains/{}", ioc)
            return domain_obj
        elif ioc_type == "url":
            # TODO: fix this
            processed_url = base64.urlsafe_b64encode("ioc".encode()).decode().strip("=")
            url_id = client.scan_url(processed_url)
            url_obj = client.get_object("/urls/{}", url_id)
            return url_obj
        elif ioc_type == "file_hash":
            file_hash = client.get_object("/files/{}", ioc)
            return file_hash
    except Exception as e:
        if e.code == "NotFoundError":
            return "NotFound"

    # return error
    return False


def check_ioc_status(ioc_obj):
    if ioc_obj == "NotFound":
        return "NotFound"

    try:
        if ioc_obj.last_analysis_stats["malicious"] > MALICIOUS_THRESHOLD:
            return "malicious"
        elif ioc_obj.last_analysis_stats["suspicious"] > SUSPICIOUS_THRESHOLD:
            return "suspicous"
        else:
            return "undetected, missing, or clean"
    except:
        return False


def display_results_summary(ioc_results):
    # display results of VT lookup with colors
    for k, v in ioc_results.items():
        if v == "malicious":
            print(
                f"---> {TextFormat.BOLD}{k}{Colors.ENDC} = {Colors.RED}{v}{Colors.ENDC}"
            )
        elif v == "suspicous":
            print(
                f"---> {TextFormat.BOLD}{k}{Colors.ENDC} = {Colors.YELLOW}{v}{Colors.ENDC}"
            )
        else:
            print(f"-> {k} = {v}")


def display_misp_results(ioc_results):
    # sort IOCs
    endpoint_iocs = []
    network_iocs = []
    for k, v in ioc_results.items():
        if v == "malicious" or v == "suspicous":
            ioc_type = ioc_type_check(k)
            if ioc_type in ["domain", "ip", "url"]:
                network_iocs.append(k)
            else:
                endpoint_iocs.append(k)

    print("-" * 30)
    print("-- IOCs to upload to MISP ---")
    print("-" * 30)
    print("=> Endpoint Indicators:")
    for i in endpoint_iocs:
        print(i)
    print()
    print("=> Network Indicators:")
    for j in network_iocs:
        print(j)


def read_ioc_file(ioc_file):
    # read iocs in file and return a list
    ioc_list = []
    with open(ioc_file) as f:
        lines = f.readlines()
        for line in lines:
            ioc_list.append(line.strip())

    return ioc_list


# iocs = ["test.com", "127.1.2.3", "10.0.2.1", "http://test3.com/dog/p=12", "90.1.2.34"]
# iocs = ["test.com", "127.1.2.3", "10.0.2.1", "test3.com", "90.1.2.34", "dog.com", "cat.net"]


if __name__ == "__main__":
    print()

    # read file
    # ioc_file = sys.argv[1]
    # assumes file is iocs.txt
    iocs = read_ioc_file("iocs.txt")

    # dictionary to hold results
    ioc_results = {}
    count = 1
    total_time = (len(iocs)) * 15
    print(f"Time to check = {total_time} seconds")

    # loop through iocs
    for ioc in iocs:
        print(f"[+] Checking IOC {ioc} ({count}/{len(iocs)})")

        # check ioc type
        ioc_type = ioc_type_check(ioc)
        # check if not false (valid type)
        if ioc_type == False:
            print(f"{RED}Error{ENDC}: Invalid IOC type for {ioc}")
            continue

        # query VT
        result = query_vt(ioc, ioc_type, client)

        # add rate limit - see https://developers.virustotal.com/reference/public-vs-premium-api
        count += 1
        sleep(15)

        # check if not false (valid result)
        if result == False:
            print(f"{RED}Error{ENDC}: VirusTotal query failed for {ioc}")
            continue

        # check ioc status
        status = check_ioc_status(result)
        if result == False:
            print(f"{RED}Error{ENDC}: VirusTotal query failed for {ioc}")
            continue

        if status == "NotFound":
            ioc_results[ioc] = "not found"
            continue

        # add to results dictionary
        ioc_results[result.id] = status

    # print results
    display_results_summary(ioc_results)
    display_misp_results(ioc_results)

    print()
    print()

    # close VT client
    client.close()