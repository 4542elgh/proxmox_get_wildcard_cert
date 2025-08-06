# Proxmox Get Wildcard Cert
This service automates the retrieval of wildcard SSL certificates from a remote server and updates local certificate files for NGINX. Wildcard certificate allow https on homelab address.

I am aware with DNS wildcard cert. I can perform renewal from homelab cerbot itself. However, I do not want to hit Certbot twice for the same certificate (public VPS + homelab), hence this script.

# Screenshot
![](./img/DiscordNotification.png)

# Features
- Connects to a remote server via SSH
- Syncs the latest Let's Encrypt certificates using `rsync`
- Cleans up old certificates locally
- Sends notifications via [Apprise](https://github.com/caronc/apprise-api) or [Discord webhook](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks)

# Usage
## 1. **Configure Environment Variables**
   Copy `.env.example` to `.env` and update its values. Notification is optional.
## 2. **Create virtual environment**
```bash
python3 -m venv .venv
```
## 3. **Activate virtual environment**
```bash
source .venv/bin/activate
```
Windows user
```ps1
.venv/bin/activate.ps1
```
## 4. **Install Dependencies**
```
pip install -r requirements.txt
```
## 5. **Run the Script**
```
python3 main.py
```
# Environment Variables
See `.env.example` for required and optional variables.

# License
GNU Affero General Public License v3.0. See [LICENSE](LICENSE).