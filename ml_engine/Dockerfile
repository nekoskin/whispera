FROM python:3.11-slim

# Установка системных зависимостей
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Создание рабочей директории
WORKDIR /app

# Копирование requirements и установка зависимостей
COPY ml_engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копирование ML движка
COPY ml_engine/ ./

# Создание директорий для моделей если их нет
RUN mkdir -p models/traffic_classifier/cnn \
    models/traffic_classifier/lstm \
    models/traffic_classifier/transformer \
    models/dpi_detector \
    models/anomaly_detector/autoencoder \
    models/anomaly_detector/isolation_forest \
    models/anomaly_detector/one_class_svm

# Порт для FastAPI
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Запуск API сервера
CMD ["python", "api_server.py"]

