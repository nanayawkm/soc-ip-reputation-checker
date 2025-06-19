import requests

API_KEY = '9978138b415bd22caf04bfe17d70d44b2befa6e828e84b6ef360e9111f50103d'  # Replace this with your actual VirusTotal API key
API_URL = "https://www.virustotal.com/api/v3/ip_addresses/"


def check_ip(ip):
    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(API_URL + ip, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        print(f"\nResults for IP: {ip}")
        print("Malicious:", stats['malicious'])
        print("Suspicious:", stats['suspicious'])
        print("Harmless:", stats['harmless'])
        print("Undetected:", stats['undetected'])
    else:
        print(f"Error: {response.status_code} - {response.text}")

if __name__ == "__main__":
    ip_input = input("Enter an IP address to check: ")
    check_ip(ip_input.strip())
