import requests

url = "http://127.0.0.1:5000/api/check-ssl"
payload = {"hostname": "www.google.com"}

try:
    response = requests.post(url, json=payload)
    print("✅ Response from backend:")
    print(response.json())
except Exception as e:
    print("❌ Error contacting backend:", str(e))
