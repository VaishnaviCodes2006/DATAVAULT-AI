# Multi-arch base image: works on linux/s390x (IBM LinuxONE) and amd64/arm64
FROM python:3.12-slim
RUN useradd --create-home --uid 10001 dv
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=dv:dv . .
USER dv
ENV DATAVAULT_DB=/app/data/audit.db
EXPOSE 8443
# Keys come from the environment (DATAVAULT_KEYS); never bake them into the image.
CMD ["sh","-c","uvicorn api:create_app --factory --host 0.0.0.0 --port ${PORT:-8443}"]
