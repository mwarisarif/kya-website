# KYA — Know Your Agent 🤖

> Decentralized Identity Infrastructure for AI Agents in the Machine Economy

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Visit%20Site-00FF85?style=for-the-badge)](https://mwarisarif.github.io/kya-website/)
[![GitHub](https://img.shields.io/badge/GitHub-Repository-181717?style=for-the-badge&logo=github)](https://github.com/mwarisarif/kya-website)
[![Python](https://img.shields.io/badge/Python-3.6+-3776AB?style=for-the-badge&logo=python)](https://python.org)
[![HTML](https://img.shields.io/badge/HTML-Frontend-E34F26?style=for-the-badge&logo=html5)](https://mwarisarif.github.io/kya-website/)

---

## 🌐 Live Website

**👉 [https://mwarisarif.github.io/kya-website/](https://mwarisarif.github.io/kya-website/)**

---

## 📌 What is KYA?

**KYA (Know Your Agent)** is a decentralized identity and trust framework for AI agents.

Just as **KYC (Know Your Customer)** verifies humans in finance, **KYA verifies machines** in the emerging machine economy — giving every autonomous AI agent a:

- 🔑 Cryptographically verifiable **DID (Decentralized Identifier)**
- 📜 **Verifiable Credential** with permissions and spend limits
- 🔍 **Real-time behavior monitoring** with anomaly detection
- 🧾 **Tamper-evident audit trail** hashed and stored on-chain
- ⭐ **Trust Score & Reputation** system (A through F grading)

---

## 🚨 The Problem

| Stat | Problem |
|------|---------|
| **45B+** | Non-human identities entering workforce by 2026 — none verifiable |
| **$14B** | Global non-compliance costs for financial firms in 2023 |
| **50%** | Internet traffic is already bots — bad bots ≈ 30% |
| **59%** | Companies hit by deepfake-driven attacks in 2025 |
| **29min** | Average AI agent breakout/attack time in 2025 |
| **0** | Existing platforms with cryptographic identity for AI agents |

---

## 🏗️ System Architecture — 5-Layer Trust Stack
Layer 01 — Agent Identity Registry
On-chain DID · ERC-8004 NFT · Owner Binding · Capability Manifest
Layer 02 — Credential & Permission Engine
VC Issuance · Session Keys · Spend Caps · Role-based ACL
Layer 03 — Runtime Behavior Monitor
Anomaly Detection ML · Circuit Breaker · Behavior Fingerprint
Layer 04 — Tamper-Evident Audit Log
Action Hashing · IPFS Storage · On-chain Anchoring · Compliance Export
Layer 05 — Trust Score & Reputation
ERC-7007 Token · Score Calculation · Cross-chain Portability

---

## 🛠️ Tech Stack

### Blockchain
- Ethereum / Polygon — Smart contracts, ERC-8004 NFTs
- Solana — High-speed agent transaction logging
- IPFS / Filecoin — Decentralized audit log storage
- Chainlink — Off-chain data oracle verification

### Identity & Auth
- W3C DID Specification
- Veramo Framework — VC issuance & management
- ERC-4337 — Account abstraction for agent wallets
- ZKSync / zkProofs — Privacy-preserving identity

### AI / ML
- Python + PyTorch — Anomaly detection model
- LangChain — Agent behavior orchestration
- Claude / OpenAI API — Agent reasoning layer
- Pinecone — Vector DB for behavior embeddings

### Backend
- Python 3.6+ — Core KYA system
- SQLite — Persistent audit log & agent registry
- FastAPI — REST API layer (coming soon)
- Redis — Session management & rate limiting

### Frontend
- HTML5 / CSS3 / JavaScript — Website & live demo
- IBM Plex Mono + Bebas Neue — Typography
- GitHub Pages — Hosting

---

## 📁 Project Structure
kya-website/
├── index.html          # Full website with interactive live demo
├── kya.py              # Python backend — complete 5-layer KYA system
└── README.md           # This file

---

## ⚙️ Run the Python Backend

### Step 1 — Clone the repository
git clone https://github.com/mwarisarif/kya-website.git
cd kya-website

### Step 2 — Create virtual environment
Windows
python -m venv venv
venv\Scripts\activate
Mac / Linux
python3 -m venv venv
source venv/bin/activate

### Step 3 — Install dependencies
pip install colorama python-dotenv

### Step 4 — Run the system
python kya.py

---

## 🗺️ Roadmap

| Phase | Timeline | Milestone |
|-------|----------|-----------|
| **Phase 1 — Foundation** | Months 1–3 | First 100 agents on testnet |
| **Phase 2 — Credentials** | Months 4–6 | First verified agent payment |
| **Phase 3 — Reputation** | Months 7–9 | 10,000 verified agent DIDs |
| **Phase 4 — Scale** | Months 10–12 | 100K agents · First enterprise deal |

---

## 💰 Revenue Model

| Stream | Model | Range |
|--------|-------|-------|
| Agent Registration Fee | One-time | $10–50 per agent NFT |
| Credential API | Monthly SaaS | $99–999 / org / month |
| Audit Log Storage | Usage-based | $0.001 per log entry |
| Enterprise KYA Suite | Annual contract | $50K–500K / year |
| Trust Score Oracle | Per-query | $0.01 per verification |

---

## 📊 Key Standards Used

| Standard | Purpose |
|----------|---------|
| ERC-8004 | NFT-based agent identity |
| ERC-7007 | AI-generated content token / reputation |
| ERC-4337 | Account abstraction for agent wallets |
| W3C DID | Decentralized identifier specification |
| W3C VC | Verifiable credentials standard |
| ZK Proofs | Privacy-preserving verification |

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License.

---

## 👤 Author

**Muhammad Waris Arif**
- GitHub: [@mwarisarif](https://github.com/mwarisarif)
- Project: [KYA — Know Your Agent](https://mwarisarif.github.io/kya-website/)

---

<div align="center">
  <strong>Built with ❤️ for the Machine Economy</strong><br>
  <sub>KYA Protocol · 2026 · All rights reserved</sub>
</div>
