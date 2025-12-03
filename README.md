# AutoSQLi Detector  
Advanced Error-Based SQL Injection Scanner for Burp Suite  
*(Burp Extension — Python/Jython)*

![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Burp](https://img.shields.io/badge/Burp%20Suite-Extension-orange)

---

## ⭐ Overview

**AutoSQLi Detector** is an advanced, fully automated **error-based SQL injection scanner** built as a Burp Suite extension.  
It passively scans **all proxy traffic**, fuzzes parameters using multiple payloads, analyzes responses for DB-specific errors, detects WAF blocks, and flags high-confidence SQL injection indicators.

Designed for **bug bounty hunters & penetration testers**, this tool provides high-accuracy SQLi detection with **near-zero false positives**.

---

# 🚀 Features

### 🔍 Detection Engine
- Error-based SQLi detection  
- Multi-payload fuzzing ( `'` `"` `)` etc.)  
- DB-specific signatures:  
  - MySQL  
  - PostgreSQL  
  - MSSQL  
  - Oracle  
- Strong response-length delta filtering (reduces noise)  
- WAF detection (ModSecurity, Cloudflare, etc.)  
- Skips:
  - Static files  
  - Images  
  - CSS/JS  
  - Fonts  
  - Huge responses (>1MB)

### 🧩 Injection Targets
- Query parameters  
- Body parameters  
- Cookies  
- Headers  

### 🛠 UI / Burp Integration
- New **AutoSQLi** tab in Burp  
- Responsive UI (auto-resize like Proxy / Repeater)  
- Built-in Request & Response viewers  
- Double-click → send injected request to **Repeater**  
- Filters:
  - All  
  - HTTP 5xx  
  - SQL Errors  
  - WAF  
- Target filter textbox (“URL contains …”)  
- Only-in-scope option  
- Clear Table / Clear All buttons

### 🚫 Noise Reduction
- Deduplicate scans  
- Deduplicate identical findings  
- Content-type filtering  
- Length-diff thresholding  
- High confidence SQLi only (no boolean/time-based)

---

# 📦 Installation (Burp Suite)

### 1. Download the extension file:
