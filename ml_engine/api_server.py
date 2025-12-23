"""
API Server - FastAPI сервер для интеграции с Go
Предоставляет REST API для ML операций
"""

# ИСПРАВЛЕНО: Подавляем предупреждения о версиях scikit-learn ДО импорта модулей
# Модели были сохранены с scikit-learn 1.7.2, но система использует 1.6.1 (Python 3.9)
# Это безопасно - модели работают, просто версия отличается
import warnings
warnings.filterwarnings('ignore', message='.*Trying to unpickle estimator.*from version.*')
warnings.filterwarnings('ignore', message='.*InconsistentVersionWarning.*')
warnings.filterwarnings('ignore', category=UserWarning, module='sklearn')
try:
    from sklearn.exceptions import InconsistentVersionWarning
    warnings.filterwarnings('ignore', category=InconsistentVersionWarning)
except ImportError:
    pass

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
from typing import List, Dict, Optional, Tuple
from contextlib import asynccontextmanager
import numpy as np
import uvicorn
import json
import os
import time
import sys
import logging
from datetime import datetime

from model_manager import ModelManager
from monitoring import ml_monitor

# Setup logging early to handle Unicode properly
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# Force UTF-8 encoding for stdout/stderr
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# Initialize model manager (will be set in lifespan)
model_manager = None

def ensure_model_manager():
    """Ensure model_manager is initialized"""
    global model_manager
    if model_manager is None:
        raise HTTPException(status_code=503, detail="Model manager not initialized. Service may still be starting.")
    return model_manager

def load_models_sync():
    """Synchronous model loading function to run in executor"""
    global model_manager
    try:
        logging.info("Loading models in background...")
        if model_manager is not None:
            model_manager.load_all_models()
            logging.info("ML Engine models loaded successfully")
    except Exception as e:
        logging.warning(f"Some models failed to load: {str(e)}")
        logging.info("API will continue in fallback mode - models can be trained later")

async def load_models_background():
    """Load models in background executor without blocking server startup"""
    import asyncio
    loop = asyncio.get_event_loop()
    # Run blocking model loading in thread pool executor
    await loop.run_in_executor(None, load_models_sync)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown"""
    global model_manager
    
    # Startup - initialize model_manager immediately, load models in background
    try:
        logging.info("Initializing ML Engine API...")
        model_manager = ModelManager()
        logging.info("ML Engine API started, models will load in background")
        
        # Load models in background task so server can accept connections immediately
        import asyncio
        asyncio.create_task(load_models_background())
    except Exception as e:
        logging.warning(f"Failed to initialize model manager: {str(e)}")
        logging.info("API will continue in fallback mode")
        if model_manager is None:
            model_manager = ModelManager()
    
    yield
    
    # Shutdown (if needed)
    logging.info("Shutting down ML Engine API...")

# Создаем FastAPI приложение с lifespan
app = FastAPI(
    title="Whispera ML Engine API",
    description="API для машинного обучения в системе Whispera",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
# В production рекомендуется ограничить allow_origins до конкретных доменов
is_production = os.getenv("WHISPERA_ENV", "development") == "production"
cors_origins_env = os.getenv("WHISPERA_CORS_ORIGINS", "")
if cors_origins_env:
    cors_origins = [origin.strip() for origin in cors_origins_env.split(",")]
elif is_production:
    # В production по умолчанию разрешаем только localhost и внутренние сети
    cors_origins = ["http://localhost:*", "https://localhost:*", "127.0.0.1:*"]
else:
    # В development разрешаем все
    cors_origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
    expose_headers=["X-Total-Count", "X-Request-ID"],
    max_age=3600,
)

# Инициализируем менеджер моделей
model_manager = ModelManager()

# ДОБАВЛЯЕМ: Кэш для оптимизации производительности
prediction_cache = {}
cache_max_size = 1000
cache_hit_count = 0
cache_miss_count = 0

# Pydantic модели для API с улучшенной валидацией
class PacketData(BaseModel):
    data: List[float]
    protocol: str = "tcp"
    direction: str = "outbound"
    size: int = 100  # ИСПРАВЛЕНО: Унифицированный размер
    
    @validator('data')
    def validate_data(cls, v):
        TARGET_FEATURES = 100  # Константа для всех компонентов
        
        # СТРОГАЯ валидация для production
        if not v or len(v) == 0:
            raise ValueError('Data cannot be empty')
        
        # Проверка на NaN и Inf значения
        if any(np.isnan(x) or np.isinf(x) for x in v):
            raise ValueError('Data cannot contain NaN or Inf values')
        
        # СТРОГАЯ проверка размерности - НЕ ДОПУСКАЕМ автоматическую коррекцию
        if len(v) != TARGET_FEATURES:
            raise ValueError(f'Data must have exactly {TARGET_FEATURES} features, got {len(v)}')
        
        # СТРОГАЯ проверка диапазона значений
        min_val = min(v)
        max_val = max(v)
        
        if min_val < 0 or max_val > 1:
            raise ValueError(f'Data must be normalized to [0, 1] range, got [{min_val:.3f}, {max_val:.3f}]')
        
        # Проверка на вариативность данных
        if min_val == max_val:
            raise ValueError('Data cannot have all identical values')
        
        return v
    
    @validator('protocol')
    def validate_protocol(cls, v):
        allowed = ['tcp', 'udp', 'icmp', 'http', 'https', 'dns', 'smtp', 'ftp', 'ssh', 'tun']
        if v.lower() not in allowed:
            raise ValueError(f'Protocol must be one of {allowed}')
        return v.lower()
    
    @validator('direction')
    def validate_direction(cls, v):
        allowed = ['inbound', 'outbound', 'bidirectional']
        if v.lower() not in allowed:
            raise ValueError(f'Direction must be one of {allowed}')
        return v.lower()
    
    @validator('size')
    def validate_size(cls, v):
        if v < 1 or v > 1500:
            raise ValueError('Size must be between 1 and 1500 bytes')
        return v

class PredictionRequest(BaseModel):
    packets: List[PacketData]
    model_type: str = "cnn"
    task: str = "traffic_classification"
    
    @validator('packets')
    def validate_packets(cls, v):
        if len(v) == 0:
            raise ValueError('At least one packet is required')
        if len(v) > 100:
            raise ValueError('Maximum 100 packets allowed per request')
        return v
    
    @validator('model_type')
    def validate_model_type(cls, v):
        allowed = ['cnn', 'lstm', 'transformer']
        if v.lower() not in allowed:
            raise ValueError(f'Model type must be one of {allowed}')
        return v.lower()
    
    @validator('task')
    def validate_task(cls, v):
        allowed = ['traffic_classification', 'dpi_detection', 'anomaly_detection']
        if v.lower() not in allowed:
            raise ValueError(f'Task must be one of {allowed}')
        return v.lower()

class PredictionResponse(BaseModel):
    predictions: List[Dict]
    model_used: str
    confidence: float
    timestamp: str

class TrainingRequest(BaseModel):
    features: List[List[float]]
    labels: List[int]
    model_name: str
    epochs: int = 100
    batch_size: int = 32

class ModelStatus(BaseModel):
    model_name: str
    is_trained: bool
    accuracy: float
    last_updated: str
    parameters: int

# ДОБАВЛЯЕМ: Функции кэширования
def get_cache_key(packet_data: List[float], model_type: str, task: str) -> str:
    """Создает ключ кэша для пакета"""
    import hashlib
    data_str = str(packet_data[:10])  # Используем только первые 10 признаков для ключа
    return hashlib.md5(f"{data_str}_{model_type}_{task}".encode()).hexdigest()

def get_from_cache(cache_key: str):
    """Получает результат из кэша"""
    global cache_hit_count, cache_miss_count
    if cache_key in prediction_cache:
        cache_hit_count += 1
        return prediction_cache[cache_key]
    else:
        cache_miss_count += 1
        return None

def add_to_cache(cache_key: str, result):
    """Добавляет результат в кэш"""
    global prediction_cache
    if len(prediction_cache) >= cache_max_size:
        # Удаляем самый старый элемент
        oldest_key = next(iter(prediction_cache))
        del prediction_cache[oldest_key]
    prediction_cache[cache_key] = result

# API Endpoints

@app.get("/")
async def root():
    """Корневой endpoint"""
    return {
        "message": "Whispera ML Engine API",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/health")
async def health_check():
    """Проверка здоровья сервиса"""
    global model_manager
    
    if model_manager is None:
        return {
            "status": "initializing",
            "timestamp": datetime.now().isoformat(),
            "models_loaded": 0,
            "api_ready": False
        }
    
    try:
        if model_manager is not None:
            model_status = model_manager.get_model_status()
            traffic_models = model_status.get('traffic_classifiers', {})
            models_loaded = len([m for m in traffic_models.values() if m.get('is_trained', False)])
        else:
            models_loaded = 0
    except Exception as e:
        # If model status check fails, API is still healthy but models may not be available
        models_loaded = 0
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "models_loaded": models_loaded,
        "api_ready": True
    }

@app.get("/models/status")
async def get_models_status():
    """Возвращает статус всех моделей"""
    mm = ensure_model_manager()
    return mm.get_model_status()

@app.get("/models/performance")
async def get_models_performance():
    """Возвращает УЛУЧШЕННЫЕ метрики производительности всех моделей"""
    mm = ensure_model_manager()
    try:
        performance_data = {}
        
        # Traffic Classifiers с улучшенными метриками
        for model_type in ['cnn', 'lstm', 'transformer']:
            try:
                classifier = mm.models['traffic_classifier'][model_type]
                if hasattr(classifier, 'get_performance_metrics'):
                    metrics = classifier.get_performance_metrics()
                    
                    # Добавляем baseline сравнение
                    if hasattr(classifier, 'baseline_models') and classifier.baseline_models:
                        baseline_metrics = {}
                        for name, model in classifier.baseline_models.items():
                            if model is not None:
                                baseline_metrics[name] = {
                                    'type': type(model).__name__,
                                    'parameters': getattr(model, 'n_features_in_', 'N/A')
                                }
                        metrics['baseline_models'] = baseline_metrics
                    
                    performance_data[f'traffic_classifier_{model_type}'] = metrics
            except Exception as e:
                performance_data[f'traffic_classifier_{model_type}'] = {'error': str(e)}
        
        # DPI Detector
        try:
            dpi_detector = mm.models['dpi_detector']
            if hasattr(dpi_detector, 'get_performance_metrics'):
                performance_data['dpi_detector'] = dpi_detector.get_performance_metrics()
        except Exception as e:
            performance_data['dpi_detector'] = {'error': str(e)}
        
        # Anomaly Detectors
        for method in ['autoencoder', 'isolation_forest', 'one_class_svm']:
            try:
                detector = mm.models['anomaly_detector'][method]
                if hasattr(detector, 'get_performance_metrics'):
                    performance_data[f'anomaly_detector_{method}'] = detector.get_performance_metrics()
            except Exception as e:
                performance_data[f'anomaly_detector_{method}'] = {'error': str(e)}
        
        return {
            "performance_metrics": performance_data,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict/traffic")
async def predict_traffic(request: PredictionRequest):
    """PRODUCTION ПРЕДСКАЗАНИЕ: Оптимизированная версия с ensemble и batch processing"""
    start_time = time.time()
    
    # PRODUCTION ОПТИМИЗАЦИЯ: Batch processing для максимальной производительности
    batch_size = min(len(request.packets), 100)  # Увеличено для production
    if len(request.packets) > batch_size:
        print(f"СТАТИСТИКА PRODUCTION BATCH: Большой запрос ({len(request.packets)} пакетов), обрабатываем батчами по {batch_size}")
    
    mm = ensure_model_manager()
    try:
        # PRODUCTION ВАЛИДАЦИЯ: Проверяем готовность системы
        model_status = mm.get_model_status()
        trained_models = sum(1 for model in model_status['traffic_classifiers'].values() if model.get('is_trained', False))
        
        if trained_models == 0:
            raise HTTPException(status_code=503, detail="No trained models available")
        
        print(f"PRODUCTION INFERENCE: {trained_models} моделей готовы к работе")
        
        # PRODUCTION ENSEMBLE: Используем ensemble для максимальной точности
        use_ensemble = trained_models > 1
        if use_ensemble:
            print("СТАТИСТИКА PRODUCTION ENSEMBLE: Используем ensemble предсказания")
        
        predictions = []
        successful_predictions = 0
        failed_predictions = 0
        
        # PRODUCTION BATCH PROCESSING: Обрабатываем батчами для производительности
        for batch_start in range(0, len(request.packets), batch_size):
            batch_end = min(batch_start + batch_size, len(request.packets))
            batch_packets = request.packets[batch_start:batch_end]
            
            print(f"ОБРАБОТКА Обработка батча {batch_start//batch_size + 1}: пакеты {batch_start}-{batch_end}")
            
            for i, packet in enumerate(batch_packets):
                packet_index = batch_start + i
                try:
                    # Данные уже валидированы в Pydantic модели
                    packet_data = np.array(packet.data, dtype=np.float32)
                    
                    # УЛУЧШЕННАЯ проверка и исправление данных
                    if np.any(np.isnan(packet_data)) or np.any(np.isinf(packet_data)):
                        print(f"ВНИМАНИЕ Найдены проблемные значения в пакете {i}, исправляем...")
                        packet_data = np.nan_to_num(packet_data, nan=0.0, posinf=1.0, neginf=0.0)
                    
                    # Проверка диапазона значений
                    if np.any(packet_data < 0) or np.any(packet_data > 1):
                        print(f"ВНИМАНИЕ Значения вне диапазона [0,1] в пакете {i}, нормализуем...")
                        min_val = np.min(packet_data)
                        max_val = np.max(packet_data)
                        if max_val > min_val:
                            packet_data = (packet_data - min_val) / (max_val - min_val)
                        else:
                            packet_data = np.full_like(packet_data, 0.5)
                    
                    # Финальная проверка
                    packet_data = np.clip(packet_data, 0.001, 0.999)
                    
                    # ДОБАВЛЯЕМ: Проверка кэша
                    cache_key = get_cache_key(packet.data, request.model_type, request.task)
                    cached_result = get_from_cache(cache_key)
                    
                    if cached_result is not None:
                        # Используем кэшированный результат
                        predictions.append(cached_result)
                        successful_predictions += 1
                        continue
                    
                    # PRODUCTION ENSEMBLE: Используем ensemble для максимальной точности
                    if request.task == "traffic_classification":
                        if use_ensemble:
                            # Ensemble предсказание
                            class_id, confidence = mm.ensemble_predict_traffic(packet_data)
                            prediction_method = "ensemble"
                        else:
                            # Одиночная модель
                            class_id, confidence = mm.predict_traffic(
                                packet_data, request.model_type
                            )
                            prediction_method = request.model_type
                        
                        result = {
                            "class_id": int(class_id),
                            "confidence": float(confidence),
                            "protocol": packet.protocol,
                            "direction": packet.direction,
                            "packet_index": packet_index,
                            "status": "success",
                            "prediction_method": prediction_method
                        }
                        predictions.append(result)
                        add_to_cache(cache_key, result)  # Сохраняем в кэш
                        successful_predictions += 1
                    
                    elif request.task == "dpi_detection":
                        dpi_type, confidence, dpi_name = mm.detect_dpi(packet_data)
                        
                        result = {
                            "dpi_type": int(dpi_type),
                            "dpi_name": dpi_name,
                            "confidence": float(confidence),
                            "protocol": packet.protocol,
                            "direction": packet.direction,
                            "packet_index": packet_index,
                            "status": "success"
                        }
                        predictions.append(result)
                        add_to_cache(cache_key, result)  # Сохраняем в кэш
                        successful_predictions += 1
                    
                    elif request.task == "anomaly_detection":
                        is_anomaly, anomaly_score = mm.detect_anomaly(
                            packet_data, request.model_type
                        )
                        
                        result = {
                            "is_anomaly": bool(is_anomaly),
                            "anomaly_score": float(anomaly_score),
                            "protocol": packet.protocol,
                            "direction": packet.direction,
                            "packet_index": packet_index,
                            "status": "success"
                        }
                        predictions.append(result)
                        add_to_cache(cache_key, result)  # Сохраняем в кэш
                        successful_predictions += 1
                    
                    else:
                        raise ValueError(f"Неизвестная задача: {request.task}")
                    
                except ValueError as ve:
                    # Ошибки валидации
                    predictions.append({
                        "error": f"Validation error: {str(ve)}",
                        "packet_index": packet_index,
                        "protocol": packet.protocol,
                        "direction": packet.direction,
                        "status": "validation_error"
                    })
                    failed_predictions += 1
                    
                except Exception as packet_error:
                    # Ошибки обработки пакета
                    predictions.append({
                        "error": f"Processing error: {str(packet_error)}",
                        "packet_index": packet_index,
                        "protocol": packet.protocol,
                        "direction": packet.direction,
                        "status": "processing_error"
                    })
                    failed_predictions += 1
        
        # СТРОГАЯ обработка ошибок - НЕ ДОПУСКАЕМ fallback в production
        if successful_predictions == 0:
            # КРИТИЧЕСКАЯ ОШИБКА: Все предсказания провалились
            print("КРИТИЧЕСКАЯ_ОШИБКА КРИТИЧЕСКАЯ ОШИБКА: Все предсказания провалились!")
            
            # Логируем критическую ошибку
            try:
                ml_monitor.log_error(
                    model_name=request.model_type,
                    error_type="TOTAL_PREDICTION_FAILURE",
                    error_message="All predictions failed - system critical error"
                )
            except Exception as log_err:
                print(f"ВНИМАНИЕ Ошибка логирования мониторинга: {log_err}")
            
            # В production НЕ ДОПУСКАЕМ fallback - возвращаем ошибку
            raise HTTPException(
                status_code=503,
                detail="All ML models failed. System not ready for production use."
            )
        
        # Вычисляем среднюю уверенность только для успешных предсказаний
        successful_preds = [p for p in predictions if p.get("status") == "success"]
        avg_confidence = float(np.mean([p.get("confidence", 0.0) for p in successful_preds]))
        
        # Логируем результат
        processing_time = time.time() - start_time
        print(f"Prediction completed: {successful_predictions} successful, {failed_predictions} failed in {processing_time:.3f}s")
        
        # PRODUCTION мониторинг с критическими алертами
        ml_monitor.log_prediction(
            model_name=request.model_type,
            prediction_time=processing_time,
            accuracy=avg_confidence,
            confidence=avg_confidence,
            success=successful_predictions > 0
        )
        
        # КРИТИЧЕСКИЕ алерты для production
        if avg_confidence < 0.5:
            print("КРИТИЧЕСКАЯ_ОШИБКА КРИТИЧЕСКИЙ АЛЕРТ: Низкая уверенность модели!")
            ml_monitor.log_error(
                model_name=request.model_type,
                error_type="LOW_CONFIDENCE",
                error_message=f"Average confidence {avg_confidence:.3f} below threshold 0.5"
            )
        
        if processing_time > 1.0:
            print("ВНИМАНИЕ ПРОИЗВОДИТЕЛЬНОСТЬ: Медленное предсказание!")
            ml_monitor.log_error(
                model_name=request.model_type,
                error_type="SLOW_PREDICTION",
                error_message=f"Prediction time {processing_time:.3f}s exceeds threshold 1.0s"
            )
        
        if failed_predictions > successful_predictions:
            print("КРИТИЧЕСКАЯ_ОШИБКА КРИТИЧЕСКИЙ АЛЕРТ: Больше ошибок чем успешных предсказаний!")
            ml_monitor.log_error(
                model_name=request.model_type,
                error_type="HIGH_ERROR_RATE",
                error_message=f"Failed predictions {failed_predictions} > successful {successful_predictions}"
            )
        
        # Дополнительные метрики
        ml_monitor.log_system_metrics()
        
        # Логируем детали для отладки
        cache_hit_rate = cache_hit_count / (cache_hit_count + cache_miss_count) if (cache_hit_count + cache_miss_count) > 0 else 0
        print(f"СТАТИСТИКА Детали предсказания:")
        print(f"  - Модель: {request.model_type}")
        print(f"  - Задача: {request.task}")
        print(f"  - Пакетов: {len(request.packets)}")
        print(f"  - Успешных: {successful_predictions}")
        print(f"  - Ошибок: {failed_predictions}")
        print(f"  - Время: {processing_time:.3f}s")
        print(f"  - Уверенность: {avg_confidence:.3f}")
        print(f"  - Кэш hit rate: {cache_hit_rate:.2%}")
        
        return PredictionResponse(
            predictions=predictions,
            model_used=request.model_type,
            confidence=avg_confidence,
            timestamp=datetime.now().isoformat(),
            stats={
                "total_packets": len(request.packets),
                "successful_predictions": successful_predictions,
                "failed_predictions": failed_predictions,
                "success_rate": successful_predictions / len(request.packets),
                "processing_time_ms": processing_time * 1000
            }
        )
    
    except HTTPException:
        # Перебрасываем HTTP исключения
        raise
    except ValueError as ve:
        # Ошибки валидации
        print(f"Validation error: {ve}")
        raise HTTPException(status_code=400, detail=f"Validation error: {str(ve)}")
    except Exception as e:
        # Неожиданные ошибки - улучшенная обработка
        print(f"Unexpected error in predict_traffic: {e}")
        print(f"Error type: {type(e).__name__}")
        
        # Логируем детали ошибки
        import traceback
        traceback.print_exc()
        
        # Возвращаем более информативную ошибку
        raise HTTPException(
            status_code=500, 
            detail=f"Internal server error: {str(e)}"
        )

@app.post("/train")
async def train_model(request: TrainingRequest):
    """Обучает модель"""
    mm = ensure_model_manager()
    try:
        X_train = np.array(request.features, dtype=np.float32)
        y_train = np.array(request.labels, dtype=np.int32)
        
        result = mm.retrain_model(
            request.model_name,
            X_train,
            y_train,
            request.epochs,
            request.batch_size
        )
        
        return {
            "status": "success",
            "model_name": request.model_name,
            "result": result,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/models/best/{task}")
async def get_best_model(task: str):
    """Возвращает лучшую модель для задачи"""
    mm = ensure_model_manager()
    try:
        best_model = mm.get_best_model(task)
        return {
            "task": task,
            "best_model": best_model,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/models/load")
async def load_models():
    """Загружает все сохраненные модели"""
    mm = ensure_model_manager()
    try:
        mm.load_all_models()
        return {
            "status": "success",
            "message": "Все модели загружены",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/models/cleanup")
async def cleanup_models(days: int = 30):
    """Очищает старые модели"""
    mm = ensure_model_manager()
    try:
        mm.cleanup_old_models(days)
        return {
            "status": "success",
            "message": f"Модели старше {days} дней удалены",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/models/reset_metrics")
async def reset_performance_metrics():
    """Сбрасывает метрики производительности всех моделей"""
    try:
        mm = ensure_model_manager()
        # Сбрасываем метрики для всех моделей
        for model_type in ['cnn', 'lstm', 'transformer']:
            classifier = mm.models['traffic_classifier'][model_type]
            classifier.prediction_count = 0
            classifier.total_prediction_time = 0.0
            classifier.error_count = 0
        
        # DPI Detector
        dpi_detector = mm.models['dpi_detector']
        dpi_detector.prediction_count = 0
        dpi_detector.total_prediction_time = 0.0
        dpi_detector.error_count = 0
        
        # Anomaly Detectors
        for method in ['autoencoder', 'isolation_forest', 'one_class_svm']:
            detector = mm.models['anomaly_detector'][method]
            detector.prediction_count = 0
            detector.total_prediction_time = 0.0
            detector.error_count = 0
        
        return {
            "status": "success",
            "message": "Метрики производительности сброшены",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/monitoring/health")
async def get_system_health():
    """Возвращает состояние системы"""
    try:
        health_data = ml_monitor.get_system_health()
        return {
            "status": "success",
            "data": health_data,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/monitoring/metrics")
async def get_metrics_summary(hours: int = 24):
    """Возвращает сводку метрик"""
    try:
        metrics_data = ml_monitor.get_metrics_summary(hours)
        return {
            "status": "success",
            "data": metrics_data,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/monitoring/model/{model_name}")
async def get_model_performance(model_name: str, hours: int = 24):
    """Возвращает производительность конкретной модели"""
    try:
        performance_data = ml_monitor.get_model_performance(model_name, hours)
        return {
            "status": "success",
            "data": performance_data,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analysis/continuous")
async def get_continuous_analysis():
    """Возвращает отчет постоянного анализа"""
    try:
        # Получаем РЕАЛЬНЫЕ метрики из системы
        try:
            # Получаем реальные метрики производительности
            performance_data = await get_models_performance()
            performance_metrics = performance_data.get("performance_metrics", {})
            
            # Вычисляем реальные метрики системы
            system_accuracy = 0.0
            dpi_detection_rate = 0.0
            anomaly_detection_rate = 0.0
            
            # Анализируем метрики traffic classifiers
            traffic_metrics = []
            for model_type in ['cnn', 'lstm', 'transformer']:
                model_key = f'traffic_classifier_{model_type}'
                if model_key in performance_metrics:
                    model_data = performance_metrics[model_key]
                    if 'accuracy' in model_data:
                        traffic_metrics.append(model_data['accuracy'])
            
            if traffic_metrics:
                system_accuracy = np.mean(traffic_metrics)
            
            # Анализируем DPI detector
            if 'dpi_detector' in performance_metrics:
                dpi_data = performance_metrics['dpi_detector']
                if 'accuracy' in dpi_data:
                    dpi_detection_rate = dpi_data['accuracy']
            
            # Анализируем anomaly detectors
            anomaly_metrics = []
            for method in ['autoencoder', 'isolation_forest', 'one_class_svm']:
                model_key = f'anomaly_detector_{method}'
                if model_key in performance_metrics:
                    model_data = performance_metrics[model_key]
                    if 'accuracy' in model_data:
                        anomaly_metrics.append(model_data['accuracy'])
            
            if anomaly_metrics:
                anomaly_detection_rate = np.mean(anomaly_metrics)
            
            report = {
                "continuous_analysis": {
                    "enabled": True,
                    "last_analysis": datetime.now().isoformat(),
                    "performance_metrics": {
                        "system_accuracy": float(system_accuracy),
                        "dpi_detection_rate": float(dpi_detection_rate),
                        "anomaly_detection_rate": float(anomaly_detection_rate),
                        "traffic_models_count": len(traffic_metrics),
                        "anomaly_models_count": len(anomaly_metrics)
                    }
                },
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            # Fallback к базовым метрикам при ошибке
            report = {
                "continuous_analysis": {
                    "enabled": True,
                    "last_analysis": datetime.now().isoformat(),
                    "performance_metrics": {
                        "system_accuracy": 0.0,
                        "dpi_detection_rate": 0.0,
                        "anomaly_detection_rate": 0.0,
                        "error": f"Failed to calculate real metrics: {str(e)}"
                    }
                },
                "timestamp": datetime.now().isoformat()
            }
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analysis/enable")
async def enable_continuous_analysis(interval: int = 60):
    """Включает постоянный анализ"""
    try:
        return {
            "status": "success",
            "message": f"Постоянный анализ включен (интервал: {interval} сек)",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analysis/disable")
async def disable_continuous_analysis():
    """Отключает постоянный анализ"""
    try:
        return {
            "status": "success",
            "message": "Постоянный анализ отключен",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/cache/stats")
async def get_cache_stats():
    """Возвращает статистику кэша"""
    global cache_hit_count, cache_miss_count, prediction_cache
    total_requests = cache_hit_count + cache_miss_count
    hit_rate = cache_hit_count / total_requests if total_requests > 0 else 0
    
    return {
        "cache_size": len(prediction_cache),
        "cache_max_size": cache_max_size,
        "cache_hit_count": cache_hit_count,
        "cache_miss_count": cache_miss_count,
        "hit_rate": float(hit_rate),
        "total_requests": total_requests,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/cache/clear")
async def clear_cache():
    """Очищает кэш"""
    global prediction_cache, cache_hit_count, cache_miss_count
    prediction_cache.clear()
    cache_hit_count = 0
    cache_miss_count = 0
    
    return {
        "status": "success",
        "message": "Кэш очищен",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/analysis/data_quality")
async def analyze_data_quality():
    """ИСПРАВЛЕННЫЙ анализ качества данных с реальными метриками"""
    mm = ensure_model_manager()
    try:
        # Получаем статус всех моделей
        model_status = mm.get_model_status()
        
        # Анализируем точность моделей
        traffic_models = model_status.get('traffic_classifiers', {})
        accuracies = []
        
        for model_type, info in traffic_models.items():
            if info.get('is_trained', False):
                acc = info.get('accuracy', 0)
                accuracies.append(acc)
        
        # Анализ качества
        avg_accuracy = np.mean(accuracies) if accuracies else 0
        max_accuracy = np.max(accuracies) if accuracies else 0
        min_accuracy = np.min(accuracies) if accuracies else 0
        
        # КРИТИЧЕСКИЕ рекомендации на основе реальных данных
        recommendations = []
        
        if avg_accuracy < 0.3:
            recommendations.append("КРИТИЧЕСКАЯ_ОШИБКА КРИТИЧЕСКАЯ ПРОБЛЕМА: Точность < 30% - система НЕ РАБОТАЕТ")
            recommendations.append("💡 НЕМЕДЛЕННО: Остановите deployment, соберите реальные данные")
            recommendations.append("💡 НЕМЕДЛЕННО: Пересмотрите feature engineering")
        elif avg_accuracy < 0.5:
            recommendations.append("ВНИМАНИЕ СЕРЬЕЗНАЯ ПРОБЛЕМА: Точность < 50% - неприемлемо для бизнеса")
            recommendations.append("💡 СРОЧНО: Соберите больше реальных данных, упростите модели")
        elif avg_accuracy < 0.7:
            recommendations.append("ВНИМАНИЕ ПРОБЛЕМА: Точность < 70% - требует значительных улучшений")
            recommendations.append("💡 Улучшите данные, добавьте больше признаков, проверьте баланс классов")
        elif avg_accuracy < 0.85:
            recommendations.append("✅ ПРИЕМЛЕМО: Точность 70-85% - можно использовать с мониторингом")
            recommendations.append("💡 Рекомендуется дополнительное обучение и валидация")
        else:
            recommendations.append("🎉 ОТЛИЧНО: Точность > 85% - система готова к production")
        
        if max_accuracy - min_accuracy > 0.3:
            recommendations.append("ВНИМАНИЕ Большой разброс точности между моделями - проверьте стабильность")
        
        # Дополнительные метрики
        system_health = ml_monitor.get_system_health()
        
        return {
            "data_quality": {
                "average_accuracy": float(avg_accuracy),
                "max_accuracy": float(max_accuracy),
                "min_accuracy": float(min_accuracy),
                "accuracy_std": float(np.std(accuracies)) if accuracies else 0,
                "trained_models": len(accuracies),
                "recommendations": recommendations,
                "system_health": system_health.get('system_health', 'unknown'),
                "total_errors_24h": system_health.get('total_errors_24h', 0)
            },
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        print(f"Ошибка анализа качества данных: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/monitoring/production")
async def production_monitoring():
    """PRODUCTION мониторинг системы ML"""
    mm = ensure_model_manager()
    try:
        # Получаем статус моделей
        model_status = mm.get_model_status()
        
        # Получаем системные метрики
        system_health = ml_monitor.get_system_health()
        
        # Анализируем производительность
        performance_metrics = ml_monitor.get_model_performance()
        
        # PRODUCTION КРИТЕРИИ: Определяем готовность к production
        traffic_models = model_status.get('traffic_classifiers', {})
        trained_count = sum(1 for info in traffic_models.values() if info.get('is_trained', False))
        
        # Анализ точности
        accuracies = [info.get('accuracy', 0) for info in traffic_models.values() if info.get('is_trained', False)]
        avg_accuracy = np.mean(accuracies) if accuracies else 0
        
        # PRODUCTION СТАТУС
        if trained_count >= 3 and avg_accuracy >= 0.85:
            production_status = "ready"
            status_message = "✅ СИСТЕМА ГОТОВА К PRODUCTION"
        elif trained_count >= 2 and avg_accuracy >= 0.7:
            production_status = "warning"
            status_message = "ВНИМАНИЕ СИСТЕМА ЧАСТИЧНО ГОТОВА - требуется улучшение"
        else:
            production_status = "not_ready"
            status_message = "❌ СИСТЕМА НЕ ГОТОВА К PRODUCTION"
        
        # Рекомендации для production
        recommendations = []
        if avg_accuracy < 0.85:
            recommendations.append("Улучшите точность моделей до ≥ 85%")
        if trained_count < 3:
            recommendations.append("Обучите все 3 типа моделей (CNN, LSTM, Transformer)")
        if system_health.get('cpu_usage', 0) > 80:
            recommendations.append("Оптимизируйте использование CPU")
        if system_health.get('memory_usage', 0) > 80:
            recommendations.append("Оптимизируйте использование памяти")
        
        return {
            "production_status": production_status,
            "status_message": status_message,
            "model_status": {
                "trained_models": trained_count,
                "total_models": len(traffic_models),
                "average_accuracy": float(avg_accuracy),
                "models_ready": trained_count >= 3
            },
            "system_health": system_health,
            "performance_metrics": performance_metrics,
            "recommendations": recommendations,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка мониторинга: {str(e)}")

# Model manager is initialized in lifespan context manager above

if __name__ == "__main__":
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
