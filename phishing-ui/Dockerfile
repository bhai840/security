FROM node:20-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
ARG REACT_APP_API_BASE_URL=/api
ARG REACT_APP_OTEL_EXPORTER_OTLP_ENDPOINT=/otel/v1/traces
ENV REACT_APP_API_BASE_URL=$REACT_APP_API_BASE_URL \
    REACT_APP_OTEL_EXPORTER_OTLP_ENDPOINT=$REACT_APP_OTEL_EXPORTER_OTLP_ENDPOINT
RUN npm run build

FROM nginx:stable-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/build /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1/ || exit 1
