# API for the free quick check (no browser). Paid plans with a browser run in Dockerfile.worker.
FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src ./src
COPY plans ./plans
COPY web ./web
COPY scripts/paddle-setup.ts ./scripts/paddle-setup.ts
USER node
ENV PORT=8787
EXPOSE 8787
CMD ["node", "src/api/server.ts"]
