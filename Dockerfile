# API for the free quick check. Paid plans with a browser get their own worker image (wave 2).
FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src ./src
COPY plans ./plans
USER node
ENV PORT=8787
EXPOSE 8787
CMD ["node", "src/api/server.ts"]
