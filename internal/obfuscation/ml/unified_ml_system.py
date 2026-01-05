"""
Unified ML System - Объединенная ML система с Python интеграцией
Интегрирует Python TensorFlow модели с Go системой
"""

import numpy as np
from typing import Dict, List, Tuple, Optional
import json
import time
from datetime import datetime

from ml_engine.model_manager import ModelManager
from ml_engine.traffic_classifier import TrafficClassifier
from ml_engine.dpi_detector import DPIDetector
from ml_engine.anomaly_detector import AnomalyDetector


class UnifiedMLSystem:
    """
    Объединенная ML система с Python TensorFlow
    Интегрирует все ML компоненты в единую систему
    """
    
    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir
        self.model_manager = ModelManager(models_dir)
        self.is_initialized = False
        self.stats = {
            'processed_packets': 0,
            'successful_predictions': 0,
            'failed_predictions': 0,
            'accuracy': 0.0,
            'last_update': None,
            'continuous_analysis': {
                'enabled': True,
                'analysis_interval': 60,  # секунды
                'last_analysis': None,
                'performance_metrics': {},
                'anomaly_threshold': 0.7,
                'dpi_detection_rate': 0.0
            }
        }
        
        # Инициализируем систему
        self.initialize()
    
    def initialize(self):
        """Инициализирует ML систему"""
        try:
            # Загружаем все модели
            self.model_manager.load_all_models()
            self.is_initialized = True
            print("Unified ML System инициализирована")
        except Exception as e:
            print(f"Ошибка инициализации ML системы: {e}")
            self.is_initialized = False
    
    def process_traffic(self, packet_data: bytes, protocol: str = "tcp", 
                       direction: str = "outbound") -> Dict:
        """
        Обрабатывает трафик через ML систему
        Возвращает результаты анализа
        """
        if not self.is_initialized:
            return self._fallback_processing(packet_data, protocol, direction)
        
        try:
            # Подготавливаем данные
            features = self._prepare_features(packet_data)
            
            # Анализ трафика
            results = {
                'packet_size': len(packet_data),
                'protocol': protocol,
                'direction': direction,
                'timestamp': datetime.now().isoformat(),
                'ml_analysis': {}
            }
            
            # 1. Классификация трафика
            try:
                best_model = self.model_manager.get_best_model('traffic_classification')
                class_id, confidence = self.model_manager.predict_traffic(features, best_model)
                results['ml_analysis']['traffic_classification'] = {
                    'class_id': int(class_id),
                    'confidence': float(confidence),
                    'model_used': best_model
                }
            except Exception as e:
                print(f"Ошибка классификации трафика: {e}")
                results['ml_analysis']['traffic_classification'] = {
                    'error': str(e),
                    'fallback': True,
                    'class_id': 0,
                    'confidence': 0.5
                }
            
            # 2. Детекция DPI
            try:
                dpi_type, confidence, dpi_name = self.model_manager.detect_dpi(features)
                results['ml_analysis']['dpi_detection'] = {
                    'dpi_type': int(dpi_type),
                    'dpi_name': dpi_name,
                    'confidence': float(confidence)
                }
            except Exception as e:
                print(f"Ошибка детекции DPI: {e}")
                results['ml_analysis']['dpi_detection'] = {
                    'error': str(e),
                    'fallback': True,
                    'dpi_type': 0,
                    'dpi_name': 'no_dpi',
                    'confidence': 0.5
                }
            
            # 3. Детекция аномалий
            try:
                best_anomaly_model = self.model_manager.get_best_model('anomaly_detection')
                is_anomaly, anomaly_score = self.model_manager.detect_anomaly(features, best_anomaly_model)
                results['ml_analysis']['anomaly_detection'] = {
                    'is_anomaly': bool(is_anomaly),
                    'anomaly_score': float(anomaly_score),
                    'model_used': best_anomaly_model
                }
            except Exception as e:
                print(f"Ошибка детекции аномалий: {e}")
                results['ml_analysis']['anomaly_detection'] = {
                    'error': str(e),
                    'fallback': True,
                    'is_anomaly': False,
                    'anomaly_score': 0.1
                }
            
            # Обновляем статистику
            self._update_stats(True)
            
            # Проверяем необходимость постоянного анализа
            self._check_continuous_analysis()
            
            return results
            
        except Exception as e:
            print(f"Ошибка обработки трафика: {e}")
            self._update_stats(False)
            return self._fallback_processing(packet_data, protocol, direction)
    
    def _prepare_features(self, packet_data: bytes) -> np.ndarray:
        """Подготавливает признаки для ML моделей - УЛУЧШЕННАЯ ВЕРСИЯ"""
        if len(packet_data) == 0:
            return np.zeros(1500, dtype=np.float32)
        
        # Конвертируем в numpy array
        packet_array = np.array(list(packet_data), dtype=np.float32)
        
        # Создаем фиксированный размер
        features = np.zeros(1500, dtype=np.float32)
        
        # 1. УЛУЧШЕННЫЕ статистические признаки (первые 30 значений)
        features[0] = len(packet_data) / 1500.0  # размер пакета
        features[1] = np.mean(packet_array) / 255.0  # среднее значение
        features[2] = np.std(packet_array) / 255.0  # стандартное отклонение
        features[3] = np.var(packet_array) / 255.0  # дисперсия
        features[4] = np.min(packet_array) / 255.0  # минимум
        features[5] = np.max(packet_array) / 255.0  # максимум
        features[6] = np.median(packet_array) / 255.0  # медиана
        features[7] = np.percentile(packet_array, 25) / 255.0  # Q1
        features[8] = np.percentile(packet_array, 75) / 255.0  # Q3
        features[9] = np.percentile(packet_array, 90) / 255.0  # 90-й перцентиль
        
        # ДОБАВЛЯЕМ новые важные признаки для DPI обхода
        features[10] = np.percentile(packet_array, 95) / 255.0  # 95-й перцентиль
        features[11] = np.percentile(packet_array, 99) / 255.0  # 99-й перцентиль
        features[12] = np.sum(packet_array == 0) / len(packet_array)  # доля нулей
        features[13] = np.sum(packet_array == 255) / len(packet_array)  # доля максимумов
        features[14] = np.sum(packet_array > 128) / len(packet_array)  # доля больших значений
        
        # Сетевые признаки для DPI детекции
        if len(packet_data) >= 20:  # Минимальный размер IP пакета
            # Анализ заголовков IP/TCP
            features[15] = packet_data[0] / 255.0  # IP версия и заголовок
            features[16] = packet_data[1] / 255.0  # TOS
            features[17] = (packet_data[2] << 8 | packet_data[3]) / 65535.0  # Длина пакета
            features[18] = packet_data[8] / 255.0  # TTL
            features[19] = packet_data[9] / 255.0  # Протокол
            
            # TCP заголовок (если есть)
            if len(packet_data) >= 40 and packet_data[9] == 6:  # TCP
                features[20] = (packet_data[20] << 8 | packet_data[21]) / 65535.0  # Source port
                features[21] = (packet_data[22] << 8 | packet_data[23]) / 65535.0  # Dest port
                features[22] = packet_data[33] / 255.0  # TCP flags
                features[23] = (packet_data[34] << 8 | packet_data[35]) / 65535.0  # Window size
        
        # 2. Частотные признаки (FFT) - следующие 64 значения
        if len(packet_array) > 1:
            fft = np.fft.fft(packet_array)
            fft_magnitude = np.abs(fft)
            # Берем первые 64 частоты
            for i in range(min(64, len(fft_magnitude))):
                features[10 + i] = fft_magnitude[i] / (np.max(fft_magnitude) + 1e-10)
        
        # 3. Байтовые паттерны - следующие 256 значений
        byte_counts = np.bincount(packet_array.astype(int), minlength=256)
        byte_counts = byte_counts / (len(packet_array) + 1e-10)  # нормализация
        for i in range(min(256, len(byte_counts))):
            features[74 + i] = byte_counts[i]
        
        # 4. Энтропия и информационные признаки
        if len(packet_array) > 0:
            # Энтропия Шеннона
            unique, counts = np.unique(packet_array, return_counts=True)
            probabilities = counts / len(packet_array)
            entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
            features[330] = entropy / 8.0  # нормализация (макс энтропия = 8 бит)
            
            # Количество уникальных байтов
            features[331] = len(unique) / 256.0
            
            # Коэффициент вариации
            if np.mean(packet_array) > 0:
                features[332] = np.std(packet_array) / (np.mean(packet_array) + 1e-10)
        
        # 5. Копируем исходные данные пакета (если есть место)
        for i, b in enumerate(packet_data):
            if i < 1000:  # Оставляем место для других признаков
                features[400 + i] = float(b) / 255.0
        
        return features
    
    def _fallback_processing(self, packet_data: bytes, protocol: str, direction: str) -> Dict:
        """Fallback обработка без ML"""
        return {
            'packet_size': len(packet_data),
            'protocol': protocol,
            'direction': direction,
            'timestamp': datetime.now().isoformat(),
            'ml_analysis': {
                'traffic_classification': {'class_id': 0, 'confidence': 0.5, 'model_used': 'fallback'},
                'dpi_detection': {'dpi_type': 0, 'dpi_name': 'no_dpi', 'confidence': 0.5},
                'anomaly_detection': {'is_anomaly': False, 'anomaly_score': 0.1, 'model_used': 'fallback'}
            },
            'fallback_mode': True
        }
    
    def _update_stats(self, success: bool):
        """Обновляет статистику"""
        self.stats['processed_packets'] += 1
        if success:
            self.stats['successful_predictions'] += 1
        else:
            self.stats['failed_predictions'] += 1
        
        if self.stats['processed_packets'] > 0:
            self.stats['accuracy'] = self.stats['successful_predictions'] / self.stats['processed_packets']
        
        self.stats['last_update'] = datetime.now().isoformat()
    
    def train_model(self, model_name: str, features: List[List[float]], 
                   labels: List[int], epochs: int = 100) -> Dict:
        """Обучает модель"""
        try:
            X_train = np.array(features, dtype=np.float32)
            y_train = np.array(labels, dtype=np.int32)
            
            result = self.model_manager.retrain_model(
                model_name, X_train, y_train, epochs, 32
            )
            
            return {
                'status': 'success',
                'model_name': model_name,
                'result': result,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def get_model_status(self) -> Dict:
        """Возвращает статус всех моделей"""
        return self.model_manager.get_model_status()
    
    def get_system_stats(self) -> Dict:
        """Возвращает статистику системы"""
        return {
            'is_initialized': self.is_initialized,
            'stats': self.stats,
            'models_status': self.get_model_status()
        }
    
    def save_system_state(self, path: str):
        """Сохраняет состояние системы"""
        state = {
            'is_initialized': self.is_initialized,
            'stats': self.stats,
            'timestamp': datetime.now().isoformat()
        }
        
        with open(path, 'w') as f:
            json.dump(state, f, indent=2)
        
        print(f"Состояние системы сохранено в {path}")
    
    def load_system_state(self, path: str):
        """Загружает состояние системы"""
        try:
            with open(path, 'r') as f:
                state = json.load(f)
            
            self.stats = state.get('stats', self.stats)
            print(f"Состояние системы загружено из {path}")
        except Exception as e:
            print(f"Ошибка загрузки состояния: {e}")
    
    def _check_continuous_analysis(self):
        """Проверяет необходимость постоянного анализа"""
        if not self.stats['continuous_analysis']['enabled']:
            return
        
        current_time = time.time()
        last_analysis = self.stats['continuous_analysis']['last_analysis']
        interval = self.stats['continuous_analysis']['analysis_interval']
        
        if last_analysis is None or (current_time - last_analysis) >= interval:
            self._perform_continuous_analysis()
            self.stats['continuous_analysis']['last_analysis'] = current_time
    
    def _perform_continuous_analysis(self):
        """Выполняет постоянный анализ системы"""
        try:
            print("🔍 Выполняем постоянный анализ системы...")
            
            # Анализ производительности моделей
            model_status = self.model_manager.get_model_status()
            
            # Анализ точности
            accuracy_metrics = {}
            for model_type, classifier in self.model_manager.models['traffic_classifier'].items():
                if classifier.is_trained:
                    accuracy_metrics[model_type] = classifier.accuracy
            
            # Анализ DPI детекции
            dpi_detector = self.model_manager.models['dpi_detector']
            dpi_accuracy = dpi_detector.accuracy if dpi_detector.is_trained else 0.0
            
            # Анализ аномалий
            anomaly_metrics = {}
            for method, detector in self.model_manager.models['anomaly_detector'].items():
                if detector.is_trained:
                    anomaly_metrics[method] = {
                        'threshold': detector.threshold,
                        'anomaly_rate': detector.anomaly_rate
                    }
            
            # Обновляем метрики
            self.stats['continuous_analysis']['performance_metrics'] = {
                'traffic_classification_accuracy': accuracy_metrics,
                'dpi_detection_accuracy': dpi_accuracy,
                'anomaly_detection_metrics': anomaly_metrics,
                'system_accuracy': self.stats['accuracy'],
                'processed_packets': self.stats['processed_packets']
            }
            
            # Проверяем на деградацию производительности
            if self.stats['accuracy'] < 0.8:
                print("⚠️ ВНИМАНИЕ: Низкая точность системы! Рекомендуется переобучение моделей")
            
            if dpi_accuracy < 0.7:
                print("⚠️ ВНИМАНИЕ: Низкая точность DPI детекции! Рекомендуется обновление данных")
            
            print("✅ Постоянный анализ завершен")
            
        except Exception as e:
            print(f"❌ Ошибка постоянного анализа: {e}")
    
    def enable_continuous_analysis(self, interval: int = 60):
        """Включает постоянный анализ"""
        self.stats['continuous_analysis']['enabled'] = True
        self.stats['continuous_analysis']['analysis_interval'] = interval
        print(f"✅ Постоянный анализ включен (интервал: {interval} сек)")
    
    def disable_continuous_analysis(self):
        """Отключает постоянный анализ"""
        self.stats['continuous_analysis']['enabled'] = False
        print("❌ Постоянный анализ отключен")
    
    def get_continuous_analysis_report(self) -> Dict:
        """Возвращает отчет постоянного анализа"""
        return {
            'enabled': self.stats['continuous_analysis']['enabled'],
            'last_analysis': self.stats['continuous_analysis']['last_analysis'],
            'performance_metrics': self.stats['continuous_analysis']['performance_metrics'],
            'system_stats': {
                'processed_packets': self.stats['processed_packets'],
                'accuracy': self.stats['accuracy'],
                'successful_predictions': self.stats['successful_predictions'],
                'failed_predictions': self.stats['failed_predictions']
            }
        }


# Функции для интеграции с Go
def create_ml_system(models_dir: str = "models") -> UnifiedMLSystem:
    """Создает ML систему"""
    return UnifiedMLSystem(models_dir)

def process_packet(ml_system: UnifiedMLSystem, packet_data: bytes, 
                  protocol: str = "tcp", direction: str = "outbound") -> str:
    """Обрабатывает пакет и возвращает JSON результат"""
    result = ml_system.process_traffic(packet_data, protocol, direction)
    return json.dumps(result)

def get_system_status(ml_system: UnifiedMLSystem) -> str:
    """Возвращает статус системы в JSON"""
    status = ml_system.get_system_stats()
    return json.dumps(status)

def train_model(ml_system: UnifiedMLSystem, model_name: str, 
               features: List[List[float]], labels: List[int], 
               epochs: int = 100) -> str:
    """Обучает модель и возвращает результат в JSON"""
    result = ml_system.train_model(model_name, features, labels, epochs)
    return json.dumps(result)
