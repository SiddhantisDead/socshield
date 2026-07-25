# syntax=docker/dockerfile:1
# Build context is the repo root (see docker-compose.yml).
FROM node:20-slim AS build
WORKDIR /app
# Docker's IPv6 route is broken in a lot of environments; Node can still try
# it first when resolving registry.npmjs.org and hang instead of falling
# back to IPv4 quickly. Force IPv4 resolution order to avoid that.
ENV NODE_OPTIONS=--dns-result-order=ipv4first
COPY frontend/package*.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund --prefer-offline
COPY frontend/ .
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
