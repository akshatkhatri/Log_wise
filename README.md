# SmartLog

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)  
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)]()  
[![Docker Compose](https://img.shields.io/badge/docker--compose-v2.0%2B-blue)]()

**SmartLog** is a full-stack, real-time, intelligent log-analysis system designed to detect bot activity and uncover hidden patterns in web server logs. It blends DevOps, backend engineering, streaming data processing, and machine learning in a resource-constrained setup (1 GB Azure VM behind CGNAT).

---

## 🎯 Core Objective

Detect bot traffic and hidden patterns in server logs **in real time** using a production-feel pipeline, while learning modern infrastructure tooling, ML pipelines, dashboards, and production workflows.

---

## 🧱 Architecture Overview

![Architecture Flowchart](docs/flowchart.png)

1. **Log Generation & Ingestion**  
   - **Source**: Nginx/access logs  
   - **Collector**: Filebeat tails logs continuously  
   - **Forwarder**: Filebeat → Kafka topic  
   - **Broker**: Kafka + Zookeeper in Docker

2. **Real-Time Processing & Feature Engineering**  
   - **Kafka Consumer** (Python) reads from Kafka  
   - Applies custom scikit-learn transformers:  
     - Dotfile Access Detector (`.git`, `.env`, etc.)  
     - Suspicious Path Detector (probing/attack paths)  
     - User-Agent Parser (curl, python-requests, headless browsers)  
     - Bot Label Generator (binary supervised model)  
   - Converts log lines into structured features → ML pipeline → bot/human prediction

3. **Prediction Storage**  
   - Results stored in **PostgreSQL** with:  
     - Timestamp  
     - Original path & user agent  
     - Extracted features  
     - Prediction label

4. **Model Lifecycle**  
   - Initial training on custom/historical labeled data  
   - **Weekly cron job** retrains model, updates serialized pipeline (joblib)

5. **Frontend Interface**  
   - **Flask** app served behind **Nginx**  
   - Homepage:  
     - Project description  
     - Architecture flowchart  
     - Links to live Grafana dashboards  
     - Feedback form

6. **Feedback Collection**  
   - Form collects: name (optional), network type, device type  
   - Handled by Flask → stored in PostgreSQL (decoupled from Kafka)

7. **Visualization & Dashboards**  
   - **Grafana** connects to PostgreSQL  
   - Panels: time-series bot/human predictions, request volumes, top suspicious paths, feedback trends

---

## 🐳 Deployment

All services containerized via **Docker Compose**:

- Kafka & Zookeeper  
- Filebeat  
- PostgreSQL  
- Flask server  
- Nginx reverse proxy  
- Grafana  
- Python Kafka consumer (ML pipeline)  
- Cron job container for retraining

**Runs on** a free-tier Azure VM (Ubuntu, 1 GB RAM, CGNAT – use port-forwarding or ngrok for testing).

---

## ⚙️ Technologies Used

- **Languages**: Python, Bash  
- **ML**: scikit-learn, custom transformers, joblib  
- **Streaming**: Kafka, Zookeeper, Filebeat  
- **Backend**: Flask, Nginx  
- **Dashboard**: Grafana  
- **Database**: PostgreSQL  
- **Infrastructure**: Docker, Docker Compose, systemd/cron  
- **Platform**: Azure (free-tier)

---

## 💡 Motivation

Logs are rich but often ignored in student projects. With SmartLog, the goals were to:

- Build a **hands-on, full-stack** system from ingestion to real-time ML to dashboards  
- Learn internals of **Kafka**, **Filebeat**, **Docker Compose**, **Grafana**  
- Tackle **custom feature engineering** for messy, unstructured logs  
- Automate retraining and deliver clean, user-facing insights

---

## 🧠 Challenges Faced

- **Imbalanced data** (bot-heavy) → custom pipelines & balanced sampling  
- Kafka + Zookeeper on 1 GB RAM → memory optimization  
- Learning Grafana panels, queries, layouts  
- Scheduling retrain + safely reloading serialized pipelines  
- CGNAT restrictions → port-forwarding, tunnels for external access

---

## 🛠️ Current Functionality

- Real-time ML pipeline: Filebeat → Kafka → Python consumer → PostgreSQL  
- Feedback form for user metadata  
- Live Grafana dashboards  
- Weekly model retraining cron  
- Full Docker Compose setup

---

## 📈 Future Plans

- Add **Grafana alert rules** for bot spikes  
- Visualize feedback data in Grafana or Superset  
- Integrate **Prometheus** for system metrics & alerts  
- WebSocket live log preview  
- Migrate feedback processing to **RQ/Redis**  
- Expose REST API endpoints for on-demand predictions  
- Role-based dashboard access  
- Archive raw logs in **InfluxDB** or another time-series DB

---

## 🚀 Getting Started

1. **Clone the repo**  
   ```bash
   git clone https://github.com/akshatkhatri/Smart-Log.git
   cd Smart-Log
2. **Create `.env`**  
   ```bash
   cp .env.example .env
   # Edit .env and configure:
   #   POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB
   #   KAFKA_BOOTSTRAP_SERVERS, ZOOKEEPER_CONNECT
   #   GRAFANA_ADMIN_USER, GRAFANA_ADMIN_PASSWORD
   #   FLASK_SECRET_KEY, etc.
   
## 🚀 Build & Run

```bash
docker-compose up --build

## 🔗 Access

- Frontend: http://localhost:8080  
- Grafana: http://localhost:3000  *(default credentials in `.env.example`)*

## 📎 Usage Context

Ideal for learners who want to:

- Master Kafka pipelines & real-time ML  
- Engineer features on unstructured logs  
- Build dashboards with Grafana & PostgreSQL  
- Orchestrate full systems on limited compute

## 🔗 Links

- GitHub: https://github.com/akshatkhatri/Smart-Log  
- Live Demo: https://smartlog.tech  
- LinkedIn Update: https://www.linkedin.com/feed/update/urn:li:activity:7334140342469832705/

## 🤝 Contributing

Contributions are welcome! Please open issues or pull requests.

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
