import requests

BASE = 'http://10.1.88.5:5000/'

response = requests.get(BASE + 'lights')

print(response.json())















