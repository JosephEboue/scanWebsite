# Introduction 
This project helps users assess the safety of a URL or IP address by scanning them with multiple security services. 
It detects common threats such as SQL injection, fuzzing vulnerabilities, and XXE attacks. The results are presented in a user-friendly interface, providing an insightful report on potential risks associated with the source.

# Installation

## Local Installation

### Frontend
```cd website/client```  
```npm install```  
```npm run dev```  

### Backend
```cd website/flask_server```  
```python server.py``` 

## Run on Docker

## Docker Usage Instructions:
Build Images:

```docker-compose build```  

Run Containers:

```docker-compose up -d```  

Access the Services:

Flask Backend: ```http://localhost:5000```

Frontend Client: ```http://localhost:8080```

Stop Containers: 
```docker-compose down```

# Sequence Diagrams 
Now the two main flows on this project are the following : 

# URL check
![URL check](https://github.com/JosephEboue/scanWebsite/blob/DevYH/sequenceDiagrams/Sequance%20diagram%201%20.drawio.png)


# IP check
![IP check](https://github.com/JosephEboue/scanWebsite/blob/DevYH/sequenceDiagrams/Sequance%20diagram%202.drawio.png)


## What does the project do?
- Scans URLs and IP addresses for security vulnerabilities.
- Detects XXE, SQL Injection, and performs fuzzing.
- Checks if an IP is blacklisted or reported for malicious activity.
- Provides actionable feedback on detected vulnerabilities.

## Benchmark of Existing Solutions:

| Tool         | Open Source   | XXE Detection | SQL Injection | Fuzzing | IP Reputation | Ease of Use |
|-------------|--------------|---------------|--------------|---------|--------------|------------|
| Burp Suite  | ❌ (Paid)     | ✅            | ✅           | ✅      | ❌           | Medium     |
| OWASP ZAP   | ✅            | ✅            | ✅           | ✅      | ❌           | Medium     |
| SQLmap      | ✅            | ❌            | ✅           | ✅      | ❌           | Hard       |
| My Scanner  | ✅            | ✅            | ✅           | ✅      | ✅           | Easy       |



## What makes our solution unique?
- Open Source & Lightweight → Free and accessible for everyone.
- User-friendly → Simple input-based scanning (URL/IP).
- IP Reputation Analysis → Checks if an IP is blacklisted or suspicious.
- Fast and Automated → Provides immediate vulnerability insights.
- Combines Vulnerability & Reputation Analysis


## Legal Compliance:
- Follow cybersecurity laws (GDPR, CFAA, NIS Directive).
- Only scan domains/IPs you own or have permission for.
- Unauthorized scanning is illegal in many countries.

## Ethical Hacking Guidelines:
- ✅ Permission-Based Testing – Only scan authorized systems.
- ✅ No Malicious Intent – Designed for defensive security, not attacks.
- ✅ Responsible Disclosure – Report vulnerabilities, don’t exploit them.


## WorkFlow
- User enters URL/IP in the input field with the fuzzing parameter.
- Clicks Scan.
- System:
    - Tests for XXE, SQLi, and fuzzing.
	- Checks IP reputation
- Returns a risk summary (e.g., "Possible SQL Injection detected", "IP reported as malicious", etc.).


