#!/bin/bash
cd /opt/mickey
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
systemctl restart mickey
