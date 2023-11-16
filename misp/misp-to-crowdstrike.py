from falconpy import IOC
from pymisp import PyMISP
from pprint import pprint
from validators import ip_address
from datetime import datetime, timedelta
from config import config

# MISP authentication vars
MISP_URL = config.MISP_URL
MISP_KEY = config.MISP_KEY
MISP_VERIFYCERT = config.MISP_VERIFYCERT
# CrowdStrike authentication vars
CLIENT_ID = config.CS_CLIENT_ID
CLIENT_SECRET = config.CS_CLIENT_SECRET

# functions 
def GetMispAttributes(misp_url, misp_key, misp_verifycert):
    # authenticate to misp 
    misp = PyMISP(misp_url, misp_key, misp_verifycert, debug=False)

    # get all IOCs with IDS flag set to true and published in last 89 days
    attributes = misp.search(controller='attributes', to_ids=1, pythonify=True, publish_timestamp='89d')

    # add IOCs to bucket
    ipv4 = []
    ipv6 = []
    domain = []
    url = []
    hostname = []
    sha256 = []
    md5 = []
    sha1 = []
    other = []

    for i in attributes:
        if (i.type == "ip-dst"):
            # check if IPv4 or IPv6
            if (ip_address.ipv4(i.value)):
                ipv4.append(i.value)
            elif (ip_address.ipv6(i.value)):
                ipv6.append(i.value)
            else:
                other.append(i.value)
        elif (i.type == "ip-dst|port"):
            addr = ipv4.append(i.value.split('|')[0])
            # check if IPv4 or IPv6
            if (ip_address.ipv4(addr)):
                ipv4.append(addr)
            elif (ip_address.ipv6(addr)):
                ipv6.append(addr)
            else:
                other.append(addr)
        elif (i.type == "domain"):
            domain.append(i.value)
        elif (i.type == "domain|ip"):
            # split domain an ip, append to respective lists
            domain.append(i.value.split('|')[0])
            addr = ipv4.append(i.value.split('|')[1])
            # check if IPv4 or IPv6
            if (ip_address.ipv4(addr)):
                ipv4.append(addr)
            elif (ip_address.ipv6(addr)):
                ipv6.append(addr)
            else:
                other.append(addr)
        elif (i.type == "url"):
            url.append(i.value)
        elif (i.type == "hostname"):
            hostname.append(i.value)
        elif (i.type == "hostname|port"):
            # split hostand and port
            hostname.append(i.value.split('|')[0])
        elif (i.type == "sha256"):
            sha256.append(i.value)
        elif (i.type == "filename|sha256"):
            # split filename and hash, append hash to sha256 list
            sha256.append(i.value.split('|')[1])
        elif (i.type == "md5"):
            md5.append(i.value)
        elif (i.type == "filename|md5"):
            # split filename and hash, append hash to md5 list
            md5.append(i.value.split('|')[1])
        elif (i.type == "sha1"):
            sha1.append(i.value)
        elif (i.type == "filename|sha1"):
            # split filename and hash, append hash to sha1 list
            sha1.append(i.value.split('|')[1])
        else:
            other.append(i.value)

    ipv4_length = len(ipv4)
    ipv6_length = len(ipv6)
    domain_length = len(domain)
    url_length = len(url)
    hostname_length = len(hostname)
    sha256_length = len(sha256)
    sha1_length = len(sha1)
    md5_length = len(md5)


    # print totals
    print(f"[+] Total MISP indicators: {ipv4_length + ipv6_length + domain_length + url_length + hostname_length + sha256_length + sha1_length + md5_length}")
    print(f"+++ Network Indicators +++ ")
    print(f"- IPv4 addresses: {ipv4_length}")
    print(f"- IPv6 addresses: {ipv6_length}")
    print(f"- Domains: {domain_length}")
    print(f"- URLs: {url_length}")
    print(f"- Hostnames: {hostname_length}")
    print(f"+++ Endpoint Indicators +++")
    print(f"- SHA256 hashes: {sha256_length}")
    print(f"- SHA1 hashes: {sha1_length}")
    print(f"- MD5 hashes: {md5_length}")
    print(f"[+] Total \"other\" IOCs: {len(other)}")
    print(f"[+] Total indicators to upload to CrowdStrike: {ipv4_length + ipv6_length + sha256_length + md5_length + domain_length}")

    # return indicators list (tuple of type and value)
    cs_indicators = {
        "ipv4": ipv4,
        "ipv6": ipv6,
        "domain": domain,
        "sha256": sha256,
        "md5": md5,
    }
    return cs_indicators


def UploadIOCs(iocs_to_upload):
    # authenticate to CrowdStrike Falcon
    falcon = IOC(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)

    # get count of iocs to upload 
    print()
    count = 0
    for i in iocs_to_upload:
        count += len(iocs_to_upload[i])
    print(f"[+] Uploading {count} MISP indicators.")

    # upload indicators
    ioc_platforms = ["Mac", "Windows", "Linux"]
    # UTC formatted date string (current date + 90 days)
    now = datetime.now() + timedelta(days=90)
    ioc_expiry_date = now.isoformat() + "Z"
    uploaded_iocs = []
    failed_iocs = []


    for ioc_type in iocs_to_upload:
        for ioc in iocs_to_upload[ioc_type]:
            response = falcon.indicator_create(action="detect", value=ioc, type=ioc_type, 
                               severity="high", platforms=ioc_platforms, applied_globally=True, 
                               retrodetects=True, description="IOC from MISP Database", expiration=ioc_expiry_date)

            if (response['status_code'] == 201):
                uploaded_iocs.append(ioc)
            elif (response['status_code'] == 400):
                try: 
                    print("[FAIL] - " + response['body']['resources'][0]['message'])
                    failed_iocs.append(ioc)
                except:
                    print(response)

    
    pprint(f"[+] upladed {len(uploaded_iocs)} new IOCs to CrowdStrike Falcon IOC Management")
    pprint(f"[+] failed to upladed {len(failed_iocs)} to CrowdStrike Falcon IOC Management (duplicates)")


    # check new CrowdStrike indicator count
    response2 = falcon.indicator_combined()
    total_iocs = response2['body']['meta']['pagination']['total']
    pprint(f"[+] There are now {total_iocs} CrowdStrike indicators.")

if __name__ == "__main__":
    print("--- script start ---")
    # connect and authenticate to CrowdStrike
    faclon = IOC(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)

    # --- Step 1: Exports all attributes from MISP --- #
    indicators = GetMispAttributes(MISP_URL, MISP_KEY, MISP_VERIFYCERT)

    # --- Step 2:  Use the CrowdStrike API to upload these IOCs as indicators to CrowdStrike --- #
    UploadIOCs(indicators)



    pprint("--- script complete ---")