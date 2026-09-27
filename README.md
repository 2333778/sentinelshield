# SentinelShield

A lightweight Web Application Firewall (WAF) and Intrusion Detection System.

## Features
- Detects SQL Injection, XSS, LFI, Command Injection
- Rate limiting per IP
- Logs all events to CSV
- Simple dashboard

## How to run
1. Activate venv: `venv\Scripts\activate`
2. Install deps: `pip install -r requirements.txt`
3. Run: `python app.py`
4. Open: http://127.0.0.1:5000