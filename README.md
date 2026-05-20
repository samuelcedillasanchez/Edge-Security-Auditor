# 🛡️ Edge Security Auditor

[![Deploy to Cloudflare Pages](https://img.shields.io/badge/Deploy-Cloudflare%20Pages-F38020?logo=cloudflare&logoColor=white)](#)
[![Vanilla JS](https://img.shields.io/badge/Frontend-Vanilla%20JS-F7DF1E?logo=javascript&logoColor=black)](#)
[![Academic Project](https://img.shields.io/badge/Project-TFC%20ASIR-blue)](#)

> **Live Demo:** [samuelcedillasanchez.com/asir](https://samuelcedillasanchez.com/asir)

**Edge Security Auditor** is a serverless web application developed as a Final Degree Project (TFC) for the ASIR (*Administración de Sistemas Informáticos y Redes*) program. 

Built entirely on **Cloudflare Pages & Workers**, it performs real-time, non-intrusive Layer 4–7 security audits without relying on a traditional monolithic backend. The tool evaluates critical infrastructure configurations and compiles the data into a dynamic, downloadable PDF report.

---

##  Key Features

* ** Layer 7 Security (HTTP Headers):** Audits web server hardening policies including HSTS, CSP, X-Frame-Options, Permissions-Policy, and Referrer-Policy.
* ** Anti-Spoofing & DNS (Layer 4/7):** Resolves infrastructure records (A, NS, MX) and verifies email spoofing protections (SPF, DMARC) via Cloudflare's DNS-over-HTTPS API.
* ** SSL/TLS Cryptographic Grading:** Integrates with the Qualys SSL Labs API to verify the real encryption grade, active protocols (e.g., TLS 1.3), and certificate expiration.
* ** OSINT & Infrastructure Footprint:** Extracts server geolocation data (City, Country, ASN) and checks for standard transparency files (`robots.txt`, `security.txt`).
* ** Dynamic PDF Reporting:** Generates a comprehensive, formatted security report directly in the client's browser using `jsPDF`.

##  Architecture & Tech Stack

This project was built with a Cloud-Native, serverless-first approach to ensure high availability, zero CORS bottlenecks, and DDoS resilience.

### Frontend (Client-Side)
* **HTML5 & CSS3:** Custom-built, responsive UI with dark-mode aesthetics, hardware-accelerated scroll reveals, and custom cursor interactions.
* **Vanilla JavaScript:** Zero-dependency DOM manipulation and state management.
* **jsPDF:** Client-side PDF generation to offload heavy processing from the edge nodes.

### Backend (Edge Computing)
* **Cloudflare Workers (V8 JavaScript):** Acts as a serverless middleware. It executes close to the user, performs parallel asynchronous `HEAD`/`GET` requests, and securely queries third-party APIs (Qualys, ipapi, Cloudflare DoH) avoiding browser CORS restrictions.

##  How It Works

1. The user inputs a target domain in the frontend.
2. A `POST` request is sent to the Cloudflare Worker (`/api/scan`).
3. The Worker uses `Promise.allSettled()` to concurrently fetch HTTP headers, DNS records, IP geolocation, and cached Qualys SSL data.
4. An internal scoring algorithm deducts points for missing security measures and assigns a final grade (A+ to F).
5. The JSON response is parsed by the frontend, rendering the dashboard and enabling the PDF export.

##  Academic Context

This project was developed by **Samuel Cedilla Sánchez** as the final capstone project (TFC) for the Higher Degree in Network and Computer Systems Administration (ASIR) at **I.E.S Clara del Rey** (Madrid, Spain - Class of 2025/2026). It demonstrates advanced knowledge in web hardening, distributed systems, and modern deployment pipelines.

---

*Designed and coded with 💻 by Samuel Cedilla Sánchez.*
