# UniFi Internet Access & Firewall Toggle Dashboard

A lightweight, modern web dashboard built with **FastAPI**, **Jinja2**, and **Tailwind CSS** to manage and toggle internet access policies on a UniFi Gateway / Controller.

---

## 🌐 Accessing the Live Application

The dashboard runs within the local private network environment.

### Network Requirements
- **Local Network Access**: You must be connected to the firm's local network (LAN / Wi-Fi).
- **Remote Access via VPN**: If connecting remotely, establish a VPN connection using **WiFiman** (or the configured Raspberry Pi gateway) to join the local subnet.

### Live Application URL
Once connected to the local network or VPN, open your browser and navigate to:
```
http://192.168.10.163:8000
```

---

## ✨ Features

- **Zone-Aware Policy Grouping**: Automatically identifies and groups multi-zone firewall policies (e.g., rules spanning both Default LAN and IoT zones) into a single unified device control.
- **Instant Access Toggle**: Flip internet access between `ALLOW` and `BLOCK` with real-time UI feedback and automated CSRF token negotiation.
- **Connected Devices Resolution**: Resolves target device MAC addresses to hostnames, friendly display names, and assigned IP addresses using UniFi active and historical client inventories.
- **Clean Architecture**: Strict separation of concerns — thin FastAPI routers, reusable Jinja2 template inheritance, centralized styling/scripts, and isolated service business logic.

---

## 🛠 Tech Stack

- **Backend**: Python 3.12, FastAPI, Uvicorn, Requests
- **Frontend**: Jinja2 Templates, Tailwind CSS (CDN), Lucide Icons
- **Integration**: UniFi OS REST API (`/proxy/network/v2/api/site/default/firewall-policies`)

---

## 📁 Project Structure

```
Unifi_Project/
├── app/
│   ├── main.py              # Application initialization & router registration
│   ├── requirements.txt     # Python dependencies
│   ├── routers/
│   │   ├── firewall.py      # REST API: toggle rule actions
│   │   └── views.py         # UI Views: dashboard & detail pages
│   ├── services/
│   │   ├── unifi_auth.py    # Authentication, session locking & token management
│   │   └── unifi_service.py # UniFi API calls, grouping & device resolution
│   ├── static/
│   │   ├── style.css        # Toggle switch and custom component styles
│   │   └── toggle.js        # Client-side toggle handlers & spinner state
│   └── templates/
│       ├── base.html        # Base layout template (header, footer, assets)
│       ├── index.html       # Dashboard with statistics & rule table
│       └── rule_detail.html # Rule detail view & connected devices list
├── logs/                    # Rotating application log files
├── Dockerfile               # Production container image definition
├── .dockerignore            # Excludes sensitive files (.env, pycache, etc.)
├── docker-compose.yml       # Raspberry Pi container deployment configuration
└── .env                     # Environment variables (credentials & host)
```

---

## ⚙️ Configuration

Create a `.env` file in the project root directory with your UniFi controller configuration:

```env
UNIFI_HOST="https://192.168.10.1"
UNIFI_USERNAME="your-unifi-username"
UNIFI_PASSWORD="your-unifi-password"
UNIFI_REMEMBER_ME=False
UNIFI_VERIFY_SSL=False
UNIFI_SESSION_TTL=3600
```

> **Security Note**: Never commit actual credentials or the `.env` file to version control.

---

## 🚀 Getting Started Locally

### 1. Prerequisites
- Python 3.11+
- Access to the target UniFi Gateway / Controller

### 2. Installation
Clone or navigate to the project directory and install dependencies:

```bash
# Create and activate virtual environment
python -m venv venv

# Windows
.\venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

# Install requirements
pip install -r app/requirements.txt
```

### 3. Running the Server
Start the development server with Uvicorn:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 🐳 Docker & Raspberry Pi Deployment

The project includes a `Dockerfile`, `.dockerignore`, and `docker-compose.yml` optimized for containerized deployment (e.g. Raspberry Pi 5).

### 1. Deploy on Raspberry Pi with Docker Compose (Recommended)
Copy the project folder to your Raspberry Pi, create your `.env` file on the Pi, and run:

```bash
# Build and start container in the background
docker compose up -d --build

# View live application logs
docker compose logs -f

# Stop container
docker compose down
```

Docker will automatically build the image natively for the Raspberry Pi's 64-bit ARM architecture (`linux/arm64`).

### 2. Manual Docker Build & Run
Alternatively, you can build and run using standard Docker CLI:

```bash
# Build the Docker image
docker build -t unifi-firewall-toggle .

# Run the container
docker run -d \
  --name unifi-firewall-toggle \
  --restart unless-stopped \
  -p 8000:8000 \
  -v $(pwd)/logs:/app/logs \
  --env-file .env \
  unifi-firewall-toggle
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Web dashboard displaying statistics and all grouped firewall rules |
| `GET` | `/rule/{rule_id}` | Detailed view of a rule and its mapped client devices |
| `POST` | `/api/firewall/toggle_rule/{rule_id}` | Toggles a rule group between `ALLOW` and `BLOCK` |
