import requests
import json

def test_analysis():
    url = "http://127.0.0.1:8001/api/v1/analyze/url"
    payload = {"url": "https://paypal-secure-verify.com/login"}
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_analysis()
