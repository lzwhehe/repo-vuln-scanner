# 漏洞 / 密钥扫描器：Vite 前端 + Express API，同一个容器提供
FROM node:22-alpine AS build
WORKDIR /app
ARG NPM_REGISTRY=https://registry.npmjs.org
# 网关把 /scanner/ 前缀转发到本容器：前端资源和 API 都以 /scanner 为前缀
ARG BASE_PATH=/scanner/
ARG API_BASE=/scanner
COPY package.json package-lock.json ./
RUN npm config set registry "$NPM_REGISTRY" && npm ci --no-audit --no-fund
COPY . .
RUN VITE_API_BASE="$API_BASE" npx vite build --base="$BASE_PATH"

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production HOST=0.0.0.0 PORT=8787 STATIC_DIR=/app/dist
COPY --from=build /app/node_modules ./node_modules
COPY package.json ./
COPY server ./server
COPY --from=build /app/dist ./dist
# 风险库（vault.json）写在 .scanner-data，用卷持久化
RUN mkdir -p /app/.scanner-data && chown -R node:node /app/.scanner-data
USER node
EXPOSE 8787
CMD ["node", "server/index.js"]
