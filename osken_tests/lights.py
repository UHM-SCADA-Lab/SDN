# File used for lights requests 

import requests

def lightsRequest(ip_address):
    lights = requests.get(ip_address)
    if (lights.json() == 0):
        light_status = 'Off'
    elif (lights.json() == 1):
        light_status = 'On'
    else:
        light_status = 'Error'
    return light_status
