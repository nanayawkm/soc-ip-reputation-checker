from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

API_KEY = '9978138b415bd22caf04bfe17d70d44b2befa6e828e84b6ef360e9111f50103d'  # Replace with your key
API_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

HTML_TEMPLATE = '''
<!doctype html>
<title>Nanayawkm's IP Reputation Checker</title>
<h2>Check IP Reputation</h2>
<form method="post">
  IP address: <input type="text" name="ip" required>
  <input type="submit" value="Check">
</form>
{% if result %}
  <h3>Results for IP: {{ ip }}</h3>
  {% if error %}
    <p style="color:red;">Error: {{ error }}</p>
  {% else %}
    <ul>
      <li>Malicious: {{ result['malicious'] }}</li>
      <li>Suspicious: {{ result['suspicious'] }}</li>
      <li>Harmless: {{ result['harmless'] }}</li>
      <li>Undetected: {{ result['undetected'] }}</li>
    </ul>
  {% endif %}
{% endif %}
'''

def get_ip_reputation(ip):
    headers = {"x-apikey": API_KEY}
    response = requests.get(API_URL + ip, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        return stats, None
    else:
        return None, f"{response.status_code} - {response.text}"

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    error = None
    ip = None
    if request.method == 'POST':
        ip = request.form['ip'].strip()
        result, error = get_ip_reputation(ip)
    return render_template_string(HTML_TEMPLATE, result=result, error=error, ip=ip)

if __name__ == '__main__':
    app.run(debug=True)
