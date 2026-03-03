@echo off
docker start n8n
timeout /t 10 /nobreak
node C:\Users\SB\purl\server.js