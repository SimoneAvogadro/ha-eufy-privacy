FROM node:20-alpine

WORKDIR /app

COPY src/package.json src/package-lock.json* ./
RUN npm ci --omit=dev 2>/dev/null || npm install --omit=dev --no-audit --no-fund

COPY src/ ./

EXPOSE 8787

CMD ["node", "server.js"]
