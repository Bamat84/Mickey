#!/bin/bash
BACKUP_DIR="/opt/mickey/backups"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p "$BACKUP_DIR"
tar -czf "$BACKUP_DIR/mickey_backup_$DATE.tar.gz" /opt/mickey/data
/opt/mickey/config.env 2>/dev/null
echo "[$(date)] Backup created"
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete
