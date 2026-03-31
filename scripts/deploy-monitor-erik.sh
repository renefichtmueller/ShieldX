#!/usr/bin/env bash
# Deploy arXiv monitor script to Erik VPS
# Run once from local machine: bash scripts/deploy-monitor-erik.sh
set -euo pipefail

ERIK="root@217.154.82.179"
SCRIPTS_DIR="/opt/scripts"

echo "=== Deploying ShieldX arXiv Monitor to Erik ==="

# 1. Copy monitor script
scp scripts/arxiv-monitor.mjs "${ERIK}:${SCRIPTS_DIR}/arxiv-monitor.mjs"
ssh "$ERIK" "chmod +x ${SCRIPTS_DIR}/arxiv-monitor.mjs"

# 2. Create .env if not exists
ssh "$ERIK" "if [ ! -f ${SCRIPTS_DIR}/.env ]; then
  cat > ${SCRIPTS_DIR}/.env << 'ENVEOF'
# ShieldX Monitor Config
ANTHROPIC_API_KEY=YOUR_KEY_HERE
GITEA_TOKEN=5df44f12b35bdbb69f78004aa494cb8dea41bc87
GITEA_BASE_URL=https://gitea.context-x.org
GITEA_USER=rene
LOG_DIR=/opt/scripts/logs
WORK_DIR=/tmp/shieldx-monitor
ENVEOF
  echo 'Created .env — set ANTHROPIC_API_KEY!'
else
  echo '.env already exists — not overwriting'
fi"

# 3. Add cron if not already set
ssh "$ERIK" "(crontab -l 2>/dev/null | grep -q 'arxiv-monitor') && echo 'Cron already set' || (crontab -l 2>/dev/null; echo '0 6 * * * node /opt/scripts/arxiv-monitor.mjs >> /opt/scripts/logs/arxiv-monitor.log 2>&1') | crontab -"

echo ""
echo "=== Done ==="
echo ""
echo "Next steps on Erik:"
echo "  1. Set ANTHROPIC_API_KEY in ${SCRIPTS_DIR}/.env"
echo "  2. Test run: node /opt/scripts/arxiv-monitor.mjs"
echo "  3. Check logs: tail -f /opt/scripts/logs/arxiv-monitor.log"
echo "  4. Cron runs daily at 6:00 UTC (8:00 Berlin)"
