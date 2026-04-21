FROM node:22-alpine

# Build cache buster — bump to force a full rebuild in hosted CI (e.g. Railway).
ARG CACHE_BUST=2026-04-21-1
RUN echo "cache_bust=${CACHE_BUST}"

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

RUN npm prune --omit=dev

EXPOSE 3000

USER node

CMD ["node", "dist/http-server.js"]
