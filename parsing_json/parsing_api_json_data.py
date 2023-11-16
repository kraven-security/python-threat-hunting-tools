import json
import requests
import validators

# URL to send Maltiverse API requests related to domain names
url = 'https://api.maltiverse.com/hostname/'

while True:
    # get user input 
    domain = input("Please enter domain to search for (or type exit to quit): ")
    # clean user input
    clean_domain = domain.strip()
    
    # check if the user wants to exit 
    if clean_domain == "exit":
        print("Goodbye.")
        break
    
    # validate the domain address
    if validators.domain(clean_domain):
        # query to Maltiverse API for a response (returned as a JSON object)
        response = requests.get(url + clean_domain)
        # parse the JSON object to just get the relevant text data
        result = json.loads(response.text)

        # check if the 'classficiation' key is present 
        try:
            # print the 'classficiation' of the IP address
            print(f"\n=> The domain {clean_domain} has been identified as {result['classification']} by Malitverse\n")
        except KeyError:
            # no classficiation avaliable from Maltiverse
            print(f"\n - The domain name {clean_domain} cannot be classified by Malitverse\n")

    
    else:
        print(f" - {clean_domain} is not a valid domain name. Please try again...\n")
        continue

    

 
