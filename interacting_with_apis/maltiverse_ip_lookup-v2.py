import ipaddress
import json
import requests

# URL to send Maltiverse API requests related to IP addresses to
url = 'https://api.maltiverse.com/ip/'

while True:
    # get user input 
    ip = input("Please enter IP to search for (or type exit to quit): ")
    # clean user input
    clean_ip = ip.strip()
    
    # check if the user wants to exit 
    if clean_ip == "exit":
        print("Goodbye.")
        break
    
    # validate the IP address
    try: 
        ipaddress.ip_address(clean_ip)
    except ValueError:
        print(f" - {clean_ip} is not a valid IP address. Please try again...\n")
        continue

    # query to Maltiverse API for a response (returned as a JSON object)
    response = requests.get(url + ip)
    # parse the JSON object to just get the relevant text data
    result = json.loads(response.text)
    
    # check if the 'classficiation' key is present 
    try:
        # print the 'classficiation' of the IP address
        print(f"\n=> The IP address {clean_ip} has been identified as {result['classification']} by Malitverse\n")
    except KeyError:
        # no classficiation avaliable from Maltiverse
        print(f"\n - The IP address {clean_ip} cannot be classified by Malitverse\n")



    


