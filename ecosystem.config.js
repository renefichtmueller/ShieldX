module.exports = {
  apps: [{
    name: "shieldx",
    cwd: "./app",
    script: "node_modules/.bin/next",
    args: "start -p 3102",
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: "512M",
    env: {
      NODE_ENV: "production",
      PATH: "/opt/homebrew/bin:/opt/homebrew/opt/postgresql@17/bin:/usr/bin:/bin:/usr/sbin:/sbin",
      DATABASE_URL: "postgresql://shieldx:shieldx_prod_2026@localhost:5432/shieldx",
      OLLAMA_ENDPOINT: "http://localhost:11434",
      SHIELDX_LOG_LEVEL: "info",
    },
  }],
}
