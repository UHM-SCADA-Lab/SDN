
import time
import requests

def areLightsOn():
    return requests.get('http://10.1.88.5:5000').json()
