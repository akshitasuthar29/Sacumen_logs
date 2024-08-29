import re

#input = "SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1"
#for reference

def parse_todict(input_str):

    result = {}
    parts = input_str.split('|')

    # The first part of the split string is the key and the rest is the value
    # In the provided example, the 'cat' key is followed by a concatenated string
    main_key_value = parts[-1]  # The last part should be the main key-value pair
    
    key_value_pattern = re.compile(r'(\w+)=([^|]+?)(?=\s\w+=|$)')
    
    # Use regex to find all key-value pairs in the main value
    matches = key_value_pattern.findall(main_key_value)
    
    # Populate the dictionary with key-value pairs
    for key, value in matches:
        result[key] = value
    
    return result


if __name__=="__main__":
    import sys
    import json
    if len(sys.argv)==2:
        input = sys.argv[1]
    else:
        print("Please provide input string")
        sys.exit()
    parsed_data = parse_todict(input)
    print("\n",json.dumps(parsed_data, indent=1))