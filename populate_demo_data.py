import requests
import json
import time

API_URL = "http://127.0.0.1:8002/api/v1"

def submit_log(filepath, parser_name):
    print(f"Submitting {filepath}...")
    with open(filepath, "rb") as f:
        response = requests.post(
            f"{API_URL}/detection/analyze-file",
            data={"parser_name": parser_name},
            files={"file": f}
        )
    if response.status_code == 200:
        print("Success:", response.json().get("summary"))
    else:
        print("Error:", response.text)

if __name__ == "__main__":
    submit_log("sample_data/apache.log", "apache")
    time.sleep(1)
    submit_log("sample_malicious.log", "apache")
