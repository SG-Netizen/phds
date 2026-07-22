# PHDS 部署指南

> 个人健康数据主权协议 — 本地开发 & 生产环境部署

---

## 目录

- [环境要求](#环境要求)
- [本地开发部署](#本地开发部署)
- [生产环境部署](#生产环境部署)
- [Nginx 反向代理配置](#nginx-反向代理配置)
- [HTTPS 配置（Let's Encrypt）](#https-配置lets-encrypt)
- [数据库迁移说明](#数据库迁移说明)
- [环境变量配置清单](#环境变量配置清单)

---

## 环境要求

| 组件 | 最低版本 | 说明 |
|------|----------|------|
| Python | 3.10+ | 运行环境 |
| pip | 21.0+ | 包管理器 |
| SQLite | 3.35+ | 内置，无需额外安装 |
| Nginx | 1.18+ | 反向代理（仅生产环境） |
| Certbot | 2.0+ | Let's Encrypt 证书管理（仅生产环境） |

---

## 本地开发部署

### 1. 克隆项目并安装依赖

```bash
git clone <repo-url> phds
cd phds
pip install -r requirements.txt
```

### 2. 直接启动 API 服务

```bash
uvicorn sdk.api.server:app --host 127.0.0.1 --port 8000 --reload
```

参数说明：
- `--reload`：代码变更后自动重启（开发模式专用）
- `--host`：监听地址，`127.0.0.1` 仅本机访问，`0.0.0.0` 允许外部访问
- `--port`：监听端口

### 3. 运行测试

```bash
python -m pytest tests/ -v
```

### 5. 运行 Demo

```bash
# 简化模式（推荐）- 手机号 + PIN
python demo/demo_lite_flow.py

# 完整流程演示（高级）
python demo/demo_flow.py
```

---

## 生产环境部署

推荐架构：

```
Internet
    │
    ▼
┌──────────────┐
│  Nginx (:443)│  ← HTTPS 终结 + 反向代理
└──────┬───────┘
       │
       ▼
┌──────────────────┐
│  Uvicorn (:8000) │  ← ASGI 服务器（多 worker）
└──────────────────┘
       │
       ▼
┌──────────────┐
│  SQLite DB   │  ← 持久化存储
└──────────────┘
```

### 1. 安装生产依赖

```bash
pip install -r requirements.txt
pip install gunicorn  # Linux 进程管理（可选）
```

### 2. 启动 Uvicorn（多 worker）

```bash
# CPU 密集型任务较少，worker 数建议 CPU 核心数 × 2
uvicorn sdk.api.server:app \
    --host 127.0.0.1 \
    --port 8000 \
    --workers 4 \
    --log-level info
```

> **Windows 注意**：Windows 不支持 `--workers` 参数，需要使用 `--workers 1`（默认值）或改用 `waitress` / `hypercorn`。

如果需要在 Linux 上使用 systemd 管理：

```ini
# /etc/systemd/system/phds.service
[Unit]
Description=PHDS API Server
After=network.target

[Service]
Type=simple
User=phds
WorkingDirectory=/opt/phds
ExecStart=/opt/phds/venv/bin/uvicorn sdk.api.server:app --host 127.0.0.1 --port 8000 --workers 4
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now phds
```

---

## Nginx 反向代理配置

### 基础配置（HTTP）

```nginx
# /etc/nginx/sites-available/phds
server {
    listen 80;
    server_name phds.example.com;

    # 日志
    access_log /var/log/nginx/phds_access.log;
    error_log  /var/log/nginx/phds_error.log;

    # 客户端请求体大小限制
    client_max_body_size 50M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # 超时设置
        proxy_connect_timeout 60s;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }

    # 静态文件（如有）
    location /static/ {
        alias /opt/phds/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
```

启用配置：

```bash
sudo ln -s /etc/nginx/sites-available/phds /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## HTTPS 配置（Let's Encrypt）

### 1. 安装 Certbot

```bash
# Ubuntu / Debian
sudo apt install certbot python3-certbot-nginx

# CentOS / RHEL
sudo yum install certbot python3-certbot-nginx
```

### 2. 获取证书

```bash
sudo certbot --nginx -d phds.example.com
```

按提示输入邮箱并同意服务条款。Certbot 会自动修改 Nginx 配置，添加 SSL 相关指令。

### 3. 自动续期

Certbot 默认已配置自动续期定时任务，可手动验证：

```bash
sudo certbot renew --dry-run
```

### 4. 完整 HTTPS Nginx 配置（参考）

Certbot 自动注入后，典型配置如下：

```nginx
server {
    listen 443 ssl http2;
    server_name phds.example.com;

    ssl_certificate     /etc/letsencrypt/live/phds.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/phds.example.com/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/phds.example.com/chain.pem;

    # 现代 TLS 安全配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # HSTS（强制 HTTPS）
    add_header Strict-Transport-Security "max-age=63072000" always;

    client_max_body_size 50M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}

# HTTP → HTTPS 重定向
server {
    listen 80;
    server_name phds.example.com;
    return 301 https://$host$request_uri;
}
```

### 安全加固建议

1. **启用防火墙**：仅开放 80/443 端口
   ```bash
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw enable
   ```

2. **文件权限**：
   ```bash
   chmod 600 /opt/phds/data/*.db
   chmod 700 /opt/phds/data
   ```

3. **禁用服务器版本信息**（Nginx）：
   ```nginx
   server_tokens off;
   ```

---

## 数据库迁移说明

PHDS 使用 SQLite 作为存储引擎，数据库文件路径默认为 `data/phds.db`。

### 数据库文件位置

| 环境 | 路径 | 说明 |
|------|------|------|
| 开发 | `data/phds.db` | 项目根目录下 |
| 生产 | `/opt/phds/data/phds.db` | 推荐独立数据目录 |

### 数据库表结构

| 表名 | 用途 | 关键字段 |
|------|------|----------|
| `bio_records` | 病历记录 | `record_id`, `patient_pubkey_hash`, `data_hash` |
| `authorizations` | 授权事件 | `request_id`, `jti`, `status` |
| `auth_log` | 审计日志 | `event_id`, `action`, `timestamp` |
| `revoked_tokens` | 撤销令牌 | `jti`, `revoked_at` |
| `chain_blocks` | 链存证（可选） | `block_index`, `data_hash`, `block_hash` |

### 备份策略

```bash
# 定期备份（推荐 crontab 每天执行）
cp /opt/phds/data/phds.db /opt/phds/backups/phds_$(date +%Y%m%d).db

# 保留最近 30 天备份
find /opt/phds/backups/ -name "phds_*.db" -mtime +30 -delete
```

### 版本升级迁移

首次部署或版本升级时，服务启动会自动调用 `init_db()` / `create_tables()`，使用 `CREATE TABLE IF NOT EXISTS` 确保幂等。**无需手动执行 SQL**。

如需手动重置数据库：

```bash
rm data/phds.db
# 重启服务后自动重建
```

---

## 环境变量配置清单

所有配置项均支持通过环境变量覆盖（前缀 `PHDS_`），也可在项目根目录放置 `.env` 文件。

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `PHDS_DATA_DIR` | `./data` | 数据目录（数据库、密钥文件） |
| `PHDS_DB_PATH` | `{DATA_DIR}/phds.db` | SQLite 数据库文件路径 |
| `PHDS_JWT_KEY_PATH` | `{DATA_DIR}/server_key.pem` | 服务端 JWT 签名密钥路径 |
| `PHDS_RATE_LIMIT_MAX` | `60` | 每分钟最大请求数 |
| `PHDS_RATE_LIMIT_WINDOW` | `60` | 限流滑动窗口（秒） |
| `PHDS_SERVER_HOST` | `127.0.0.1` | 服务监听地址 |
| `PHDS_SERVER_PORT` | `8000` | 服务监听端口 |

### .env 示例

```bash
# .env（放置在项目根目录）
PHDS_DATA_DIR=/opt/phds/data
PHDS_RATE_LIMIT_MAX=120
PHDS_SERVER_HOST=0.0.0.0
PHDS_SERVER_PORT=8000
```

### 生产环境推荐值

```bash
PHDS_DATA_DIR=/opt/phds/data
PHDS_RATE_LIMIT_MAX=100         # 适当放宽
PHDS_RATE_LIMIT_WINDOW=60
PHDS_SERVER_HOST=127.0.0.1      # 仅本地监听，由 Nginx 代理
PHDS_SERVER_PORT=8000
```
