import ipaddress
from maltiverse import Maltiverse

# instantiate object to interact with Maltiverse API
api = Maltiverse()
# api = Maltiverse(auth_token="...")

while True:
    # get user input 
    ip = input("Please enter IP to search for (or type exit to quit): ")
    # clean user input
    clean_ip = ip.strip()

    # check if the user wants to exit 
    if clean_ip == "quit":
        print("Goodbye.")
        break
    
    # validate the IP address
    try: 
        ipaddress.ip_address(clean_ip)
    except ValueError:
        print(f" - {clean_ip} is not a valid IP address. Please try again...\n")
        continue

    # query Maltiverse API for data about the result
    result = api.ip_get(clean_ip)

    # check if the 'classficiation' key is present 
    try:
        # print the 'classficiation' of the IP address
        print(f"\n=> The IP address {clean_ip} has been identified as {result['classification']} by Malitverse\n")
    except KeyError:
        # no classficiation avaliable from Maltiverse
        print(f"\n - The IP address {clean_ip} cannot be classified by Malitverse\n")




       



