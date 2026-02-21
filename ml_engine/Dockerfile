FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY ml_engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ml_engine/ ./

RUN mkdir -p models/traffic_classifier/cnn \
    models/traffic_classifier/lstm \
    models/traffic_classifier/transformer \
    models/dpi_detector \
    models/anomaly_detector/autoencoder \
    models/anomaly_detector/isolation_forest \
    models/anomaly_detector/one_class_svm

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python", "api_server.py"]

