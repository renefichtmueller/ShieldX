#!/bin/bash
export PATH="/opt/homebrew/bin:$PATH"
cd ~/shieldx
echo "=== ShieldX Deploy ==="
echo "Host: $(hostname), Node: $(node -v)"
pm2 delete shieldx 2>/dev/null || true
pm2 start ecosystem.config.js
pm2 save
sleep 3
pm2 list
echo "HTTP check:"
curl -s -o /dev/null -w "%{http_code}" http://localhost:3102/ || echo "not ready"
echo ""
echo "=== Done ==="
