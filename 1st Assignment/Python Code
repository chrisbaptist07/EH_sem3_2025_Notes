import hashlib, requests, json

API_KEY = "ebeae4b765150762ff8073c0b0b36582879b1a7d339aa2c16c573a3d0535b937"
FILE = "testfile.txt"

with open(FILE, "rb") as f:
    file_hash = hashlib.sha256(f.read()).hexdigest()

url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
headers = {"x-apikey": API_KEY}
response = requests.get(url, headers=headers)

print(response.json()["data"]["attributes"]["last_analysis_stats"])
