FROM php:8.3-cli-alpine@sha256:66e726c387bd539888c3d05f4e2c8b03c85566805a02476fdfb7ca8d3592c2db
RUN apk upgrade --no-cache
WORKDIR /app
COPY src ./src
USER www-data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/ || exit 1
CMD ["php", "-S", "0.0.0.0:8080", "-t", "src"]
