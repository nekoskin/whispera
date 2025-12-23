"""
Model Manager - Менеджер моделей машинного обучения
Управляет всеми ML моделями и их жизненным циклом
"""

import os
import json
import numpy as np
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import threading
import time
import logging
import warnings

# ИСПРАВЛЕНО: Подавляем предупреждения о версиях scikit-learn глобально
# Модели были сохранены с scikit-learn 1.7.2, но система использует 1.6.1 (Python 3.9)
# Это безопасно - модели работают, просто версия отличается
warnings.filterwarnings('ignore', message='.*Trying to unpickle estimator.*from version.*', category=UserWarning)
warnings.filterwarnings('ignore', message='.*InconsistentVersionWarning.*', category=UserWarning)
try:
    from sklearn.exceptions import InconsistentVersionWarning
    warnings.filterwarnings('ignore', category=InconsistentVersionWarning)
except ImportError:
    pass

from traffic_classifier import TrafficClassifier
from dpi_detector import DPIDetector
from anomaly_detector import AnomalyDetector


class ModelManager:
    """
    Менеджер всех ML моделей
    Управляет обучением, загрузкой, сохранением и инференсом
    """
    
    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir
        self.models = {}
        self.lock = threading.RLock()
        
        # Настройка логирования
        self._setup_logging()
        
        # Создаем директории
        os.makedirs(models_dir, exist_ok=True)
        os.makedirs(os.path.join(models_dir, "traffic_classifier"), exist_ok=True)
        os.makedirs(os.path.join(models_dir, "dpi_detector"), exist_ok=True)
        os.makedirs(os.path.join(models_dir, "anomaly_detector"), exist_ok=True)
        
        # Инициализируем модели
        self._initialize_models()
    
    def _setup_logging(self):
        """Настраивает систему логирования"""
        import sys
        
        # Force UTF-8 encoding for stdout/stderr
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8')
        
        # Create handlers with UTF-8 encoding
        file_handler = logging.FileHandler('ml_engine.log', encoding='utf-8')
        console_handler = logging.StreamHandler(sys.stdout)
        
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        root_logger.handlers = []  # Clear existing handlers
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)
        
        self.logger = logging.getLogger('ModelManager')
        self.logger.info("ModelManager initialized")
    
    def _initialize_models(self):
        """Инициализирует все модели"""
        with self.lock:
            # ИСПРАВЛЕНО: Унифицированные размеры для всех моделей
            TARGET_FEATURES = 100  # Константа для всех компонентов
            self.models['traffic_classifier'] = {
                'cnn': TrafficClassifier('cnn', TARGET_FEATURES, 22),
                'lstm': TrafficClassifier('lstm', TARGET_FEATURES, 22),
                'transformer': TrafficClassifier('transformer', TARGET_FEATURES, 22)
            }
            
            # DPI Detector
            self.models['dpi_detector'] = DPIDetector()
            
            # Anomaly Detector
            self.models['anomaly_detector'] = {
                'autoencoder': AnomalyDetector('autoencoder'),
                'isolation_forest': AnomalyDetector('isolation_forest'),
                'one_class_svm': AnomalyDetector('one_class_svm')
            }
    
    def train_traffic_classifier(self, model_type: str, X_train: np.ndarray, y_train: np.ndarray,
                                X_val: np.ndarray = None, y_val: np.ndarray = None,
                                epochs: int = 100, batch_size: int = 32, class_weight: dict = None) -> Dict:
        """Обучает классификатор трафика"""
        with self.lock:
            if model_type not in self.models['traffic_classifier']:
                raise ValueError(f"Неизвестный тип модели: {model_type}")
            
            classifier = self.models['traffic_classifier'][model_type]
            result = classifier.train(X_train, y_train, X_val, y_val, epochs, batch_size, class_weight)
            
            # Сохраняем модель
            model_path = os.path.join(self.models_dir, "traffic_classifier", model_type)
            classifier.save_model(model_path)
            
            return result
    
    def train_dpi_detector(self, X_train: np.ndarray, y_train: np.ndarray,
                          X_val: np.ndarray = None, y_val: np.ndarray = None,
                          epochs: int = 100, batch_size: int = 32) -> Dict:
        """Обучает детектор DPI"""
        with self.lock:
            detector = self.models['dpi_detector']
            result = detector.train(X_train, y_train, X_val, y_val, epochs, batch_size)
            
            # Сохраняем модель
            model_path = os.path.join(self.models_dir, "dpi_detector")
            detector.save_model(model_path)
            
            return result
    
    def train_anomaly_detector(self, method: str, X_train: np.ndarray,
                              epochs: int = 100, batch_size: int = 32) -> Dict:
        """Обучает детектор аномалий"""
        with self.lock:
            if method not in self.models['anomaly_detector']:
                raise ValueError(f"Неизвестный метод: {method}")
            
            detector = self.models['anomaly_detector'][method]
            result = detector.train(X_train, epochs, batch_size)
            
            # Сохраняем модель
            model_path = os.path.join(self.models_dir, "anomaly_detector", method)
            detector.save_model(model_path)
            
            return result
    
    def load_all_models(self):
        """Загружает все сохраненные модели"""
        with self.lock:
            loaded_count = 0
            failed_count = 0
            
            # Загружаем Traffic Classifiers
            for model_type in ['cnn', 'lstm', 'transformer']:
                model_path = os.path.join(self.models_dir, "traffic_classifier", model_type)
                if os.path.exists(os.path.join(model_path, 'model.h5')):
                    try:
                        self.models['traffic_classifier'][model_type].load_model(model_path)
                        self.logger.info(f"Traffic Classifier ({model_type}) loaded successfully")
                        loaded_count += 1
                    except Exception as e:
                        # Model may be incompatible with current TensorFlow version - skip it
                        self.logger.warning(f"Failed to load Traffic Classifier ({model_type}): {str(e)}")
                        self.logger.info(f"Skipping incompatible model ({model_type}), API will work without it")
                        failed_count += 1
                        # Remove incompatible model file to prevent future errors
                        try:
                            import shutil
                            backup_path = model_path + ".incompatible"
                            if not os.path.exists(backup_path):
                                shutil.move(model_path, backup_path)
                                self.logger.info(f"Moved incompatible model to {backup_path}")
                        except Exception as cleanup_error:
                            self.logger.warning(f"Could not clean up incompatible model: {cleanup_error}")
            
            # Загружаем DPI Detector
            dpi_path = os.path.join(self.models_dir, "dpi_detector")
            if os.path.exists(os.path.join(dpi_path, 'dpi_detector.h5')):
                try:
                    self.models['dpi_detector'].load_model(dpi_path)
                    self.logger.info("DPI Detector loaded successfully")
                    loaded_count += 1
                except Exception as e:
                    self.logger.warning(f"Failed to load DPI Detector: {str(e)}")
                    self.logger.info("Skipping incompatible DPI Detector, API will work without it")
                    failed_count += 1
            
            # Загружаем Anomaly Detectors
            for method in ['autoencoder', 'isolation_forest', 'one_class_svm']:
                model_path = os.path.join(self.models_dir, "anomaly_detector", method)
                if os.path.exists(os.path.join(model_path, 'metadata.json')):
                    try:
                        self.models['anomaly_detector'][method].load_model(model_path)
                        self.logger.info(f"Anomaly Detector ({method}) loaded successfully")
                        loaded_count += 1
                    except Exception as e:
                        self.logger.warning(f"Failed to load Anomaly Detector ({method}): {str(e)}")
                        self.logger.info(f"Skipping incompatible Anomaly Detector ({method}), API will work without it")
                        failed_count += 1
            
            # Summary
            self.logger.info(f"Model loading complete: {loaded_count} loaded, {failed_count} failed/skipped")
            if loaded_count == 0:
                self.logger.warning("No models loaded - API will work in fallback mode. Train models to enable ML features.")
    
    def predict_traffic(self, packet_data: np.ndarray, model_type: str = "cnn") -> Tuple[int, float]:
        """Предсказывает класс трафика"""
        with self.lock:
            if model_type not in self.models['traffic_classifier']:
                raise ValueError(f"Неизвестный тип модели: {model_type}")
            
            classifier = self.models['traffic_classifier'][model_type]
            if not classifier.is_trained:
                raise ValueError(f"Модель {model_type} не обучена")
            
            classes, probabilities = classifier.predict(packet_data.reshape(1, -1))
            return classes[0], probabilities[0]
    
    def detect_dpi(self, packet_data: np.ndarray) -> Tuple[int, float, str]:
        """Детектирует DPI в пакете"""
        with self.lock:
            if not self.models['dpi_detector'].is_trained:
                raise ValueError("DPI Detector не обучен")
            
            return self.models['dpi_detector'].detect_dpi(packet_data)
    
    def detect_anomaly(self, packet_data: np.ndarray, method: str = "autoencoder") -> Tuple[bool, float]:
        """Детектирует аномалию в пакете"""
        with self.lock:
            if method not in self.models['anomaly_detector']:
                raise ValueError(f"Неизвестный метод: {method}")
            
            detector = self.models['anomaly_detector'][method]
            if not detector.is_trained:
                raise ValueError(f"Anomaly Detector ({method}) не обучен")
            
            return detector.detect_anomaly(packet_data)
    
    def get_model_status(self) -> Dict:
        """Возвращает статус всех моделей"""
        with self.lock:
            status = {
                'traffic_classifiers': {},
                'dpi_detector': {},
                'anomaly_detectors': {},
                'last_updated': datetime.now().isoformat()
            }
            
            # Traffic Classifiers
            for model_type, classifier in self.models['traffic_classifier'].items():
                status['traffic_classifiers'][model_type] = classifier.get_model_info()
            
            # DPI Detector
            status['dpi_detector'] = self.models['dpi_detector'].get_model_info()
            
            # Anomaly Detectors
            for method, detector in self.models['anomaly_detector'].items():
                status['anomaly_detectors'][method] = detector.get_model_info()
            
            return status
    
    def retrain_model(self, model_name: str, new_data: np.ndarray, new_labels: np.ndarray = None,
                     epochs: int = 50, batch_size: int = 32) -> Dict:
        """Переобучает модель на новых данных"""
        with self.lock:
            if model_name == "dpi_detector":
                if new_labels is None:
                    raise ValueError("DPI Detector требует метки")
                return self.train_dpi_detector(new_data, new_labels, epochs=epochs, batch_size=batch_size)
            
            elif model_name.startswith("traffic_classifier_"):
                model_type = model_name.split("_")[-1]
                if new_labels is None:
                    raise ValueError("Traffic Classifier требует метки")
                return self.train_traffic_classifier(model_type, new_data, new_labels, epochs=epochs, batch_size=batch_size)
            
            elif model_name.startswith("anomaly_detector_"):
                method = model_name.split("_")[-1]
                return self.train_anomaly_detector(method, new_data, epochs=epochs, batch_size=batch_size)
            
            else:
                raise ValueError(f"Неизвестная модель: {model_name}")
    
    def get_best_model(self, task: str) -> str:
        """Возвращает лучшую модель для задачи с ensemble подходом"""
        with self.lock:
            if task == "traffic_classification":
                # PRODUCTION ENSEMBLE: Выбираем лучшую модель с fallback
                best_accuracy = 0.0
                best_model = "cnn"  # CNN как default для стабильности
                
                # Проверяем все модели и выбираем лучшую
                for model_type, classifier in self.models['traffic_classifier'].items():
                    if classifier.is_trained and classifier.accuracy > best_accuracy:
                        best_accuracy = classifier.accuracy
                        best_model = model_type
                
                # PRODUCTION FALLBACK: Если все модели плохие, используем CNN
                if best_accuracy < 0.7:
                    print(f"⚠️ ВНИМАНИЕ: Лучшая точность {best_accuracy:.3f} < 0.7, используем CNN как fallback")
                    return "cnn"
                
                return best_model
            
            elif task == "anomaly_detection":
                # PRODUCTION ENSEMBLE: Приоритет по стабильности
                if self.models['anomaly_detector']['isolation_forest'].is_trained:
                    return "isolation_forest"  # Самый стабильный
                elif self.models['anomaly_detector']['autoencoder'].is_trained:
                    return "autoencoder"  # Хороший для production
                else:
                    return "one_class_svm"  # Fallback
            
            else:
                raise ValueError(f"Неизвестная задача: {task}")
    
    def ensemble_predict_traffic(self, packet_data: np.ndarray) -> Tuple[int, float]:
        """ИСПРАВЛЕННЫЙ ENSEMBLE: Взвешенное голосование с учетом качества моделей"""
        with self.lock:
            predictions = []
            weights = []
            
            # Собираем предсказания от всех обученных моделей с весами
            for model_type, classifier in self.models['traffic_classifier'].items():
                if classifier.is_trained and classifier.accuracy > 0.7:  # Только качественные модели
                    try:
                        class_id, confidence = classifier.predict(packet_data.reshape(1, -1))
                        predictions.append(class_id[0])
                        # Вес = точность модели * уверенность предсказания
                        weight = classifier.accuracy * confidence[0]
                        weights.append(weight)
                    except Exception as e:
                        print(f"⚠️ Ошибка предсказания {model_type}: {e}")
                        continue
            
            if not predictions:
                # КРИТИЧЕСКАЯ ОШИБКА: Нет качественных моделей
                print("🚨 КРИТИЧЕСКАЯ ОШИБКА: Нет качественных моделей для ensemble")
                raise ValueError("No trained models with sufficient accuracy available")
            
            # ИСПРАВЛЕННЫЙ ENSEMBLE: Взвешенное голосование
            if len(predictions) == 1:
                # Только одна модель работает
                return predictions[0], weights[0]
            else:
                # Несколько моделей - используем взвешенное голосование
                from collections import defaultdict
                weighted_votes = defaultdict(float)
                
                for pred, weight in zip(predictions, weights):
                    weighted_votes[pred] += weight
                
                # Выбираем класс с максимальным весом
                best_class = max(weighted_votes, key=weighted_votes.get)
                best_confidence = weighted_votes[best_class] / sum(weights)
                
                print(f"📊 ENSEMBLE: {len(predictions)} моделей, класс {best_class}, уверенность: {best_confidence:.3f}")
                return best_class, best_confidence
    
    def cleanup_old_models(self, days: int = 30):
        """Удаляет старые модели"""
        cutoff_time = time.time() - (days * 24 * 60 * 60)
        
        for root, dirs, files in os.walk(self.models_dir):
            for file in files:
                if file.endswith('.h5') or file.endswith('.pkl'):
                    file_path = os.path.join(root, file)
                    if os.path.getmtime(file_path) < cutoff_time:
                        try:
                            os.remove(file_path)
                            print(f"Удален старый файл: {file_path}")
                        except Exception as e:
                            print(f"Ошибка удаления {file_path}: {e}")
