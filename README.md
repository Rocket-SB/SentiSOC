# 🛡️ SentiSOC - Microservices Security Operations Center

SentiSOC is a modernized, microservices-based Information System Architecture equipped with centralized observability, real-time security monitoring, and incident response capabilities. 

Built as a containerized environment, it demonstrates a complete SOC workflow: from edge-routing and rate-limiting to metric scraping, alert triggering, and automated Discord notifications.

## ✨ Key Features

* **Microservices Architecture:** Independently scalable Python/Flask services handling Authentication, Resource Management, and Reservations.
* **Real-Time Threat Detection:** NGINX rate-limiting coupled with Prometheus metrics to detect and mitigate brute-force attacks instantly.
* **Automated Alerting Pipeline:** Prometheus rules trigger Alertmanager, which pushes native JSON payloads to Discord webhooks and synchronizes with the frontend's audit log.
* **Centralized Observability:** Hardware metrics (CPU, RAM, Disk) and application logs are collected and queryable via Prometheus and Loki.
* **Single Sign-On (SSO):** Secure Identity and Access Management integrated through Keycloak.
* **Executive Dashboard:** A custom Grafana-style frontend with real-time gauges, incident triage capabilities (Pending/Solved/Rejected), and printable PDF executive reports.

## 🛠️ Technology Stack

* **Backend:** Python 3.12, Flask
* **Frontend:** HTML5, CSS3, Jinja2 (Custom Grafana-inspired UI)
* **Infrastructure & Routing:** Docker, Docker Compose, NGINX
* **Monitoring & SecOps:** Prometheus, Alertmanager, Grafana Loki
* **Identity & Access (IAM):** Keycloak

## 🚀 Getting Started

### Prerequisites
* Docker and Docker Compose installed on your host machine.
* A Discord Webhook URL (for Alertmanager notifications).

### Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/yourusername/SentiSOC.git](https://github.com/yourusername/SentiSOC.git)
   cd SentiSOC