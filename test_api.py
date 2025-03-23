import requests

url = "http://127.0.0.1:5000/send-otp"
data = {"email": "test@example.com"}
headers = {"Content-Type": "application/json"}

response = requests.post(url, json=data, headers=headers)
print("Status Code:", response.status_code)
print("Response:", response.json())
