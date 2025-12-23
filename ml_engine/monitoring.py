"""
Monitoring - Система мониторинга и логирования для ML Engine
Отслеживает производительность, ошибки и метрики моделей
"""

import logging
import time
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import numpy as np
from collections import defaultdict, deque
import threading
import psutil


class MLMonitor:
    """
    Мониторинг ML системы
    Отслеживает производительность, ошибки и метрики
    """
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = log_dir
        self.metrics = defaultdict(list)
        self.errors = deque(maxlen=1000)
        self.performance_data = deque(maxlen=1000)
        self.lock = threading.RLock()
        
        # Создаем директории
        os.makedirs(log_dir, exist_ok=True)
        os.makedirs(os.path.join(log_dir, "metrics"), exist_ok=True)
        os.makedirs(os.path.join(log_dir, "errors"), exist_ok=True)
        os.makedirs(os.path.join(log_dir, "performance"), exist_ok=True)
        
        # Настройка логирования
        self._setup_logging()
        
        # Инициализация метрик
        self._initialize_metrics()
    
    def _setup_logging(self):
        """Настраивает систему логирования"""
        # Основной логгер
        self.logger = logging.getLogger('MLMonitor')
        self.logger.setLevel(logging.INFO)
        
        # Обработчик для файла
        file_handler = logging.FileHandler(
            os.path.join(self.log_dir, 'ml_monitor.log'),
            encoding='utf-8'
        )
        file_handler.setLevel(logging.INFO)
        
        # Обработчик для консоли
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Форматтер
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Добавляем обработчики
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Логгер для ошибок
        self.error_logger = logging.getLogger('MLErrors')
        self.error_logger.setLevel(logging.ERROR)
        
        error_handler = logging.FileHandler(
            os.path.join(self.log_dir, 'errors', 'ml_errors.log'),
            encoding='utf-8'
        )
        error_handler.setFormatter(formatter)
        self.error_logger.addHandler(error_handler)
    
    def _initialize_metrics(self):
        """Инициализирует метрики"""
        self.metrics = {
            'predictions': [],
            'training_time': [],
            'accuracy': [],
            'loss': [],
            'memory_usage': [],
            'cpu_usage': [],
            'error_rate': [],
            'throughput': []
        }
    
    def log_prediction(self, model_name: str, prediction_time: float, 
                      accuracy: float, confidence: float, success: bool):
        """Логирует предсказание"""
        with self.lock:
            prediction_data = {
                'timestamp': datetime.now().isoformat(),
                'model_name': model_name,
                'prediction_time': prediction_time,
                'accuracy': accuracy,
                'confidence': confidence,
                'success': success
            }
            
            self.metrics['predictions'].append(prediction_data)
            self.performance_data.append(prediction_data)
            
            # Логируем
            self.logger.info(
                f"Prediction: {model_name}, "
                f"Time: {prediction_time:.3f}s, "
                f"Accuracy: {accuracy:.3f}, "
                f"Confidence: {confidence:.3f}, "
                f"Success: {success}"
            )
    
    def log_training(self, model_name: str, training_time: float, 
                    epochs: int, final_accuracy: float, final_loss: float):
        """Логирует обучение модели"""
        with self.lock:
            training_data = {
                'timestamp': datetime.now().isoformat(),
                'model_name': model_name,
                'training_time': training_time,
                'epochs': epochs,
                'final_accuracy': final_accuracy,
                'final_loss': final_loss
            }
            
            self.metrics['training_time'].append(training_data)
            
            # Логируем
            self.logger.info(
                f"Training: {model_name}, "
                f"Time: {training_time:.3f}s, "
                f"Epochs: {epochs}, "
                f"Accuracy: {final_accuracy:.3f}, "
                f"Loss: {final_loss:.3f}"
            )
    
    def log_error(self, model_name: str, error_type: str, error_message: str, 
                  stack_trace: str = None):
        """Логирует ошибку"""
        with self.lock:
            error_data = {
                'timestamp': datetime.now().isoformat(),
                'model_name': model_name,
                'error_type': error_type,
                'error_message': error_message,
                'stack_trace': stack_trace
            }
            
            self.errors.append(error_data)
            
            # Логируем ошибку
            self.error_logger.error(
                f"Error in {model_name}: {error_type} - {error_message}"
            )
            
            if stack_trace:
                self.error_logger.error(f"Stack trace: {stack_trace}")
    
    def log_system_metrics(self):
        """Логирует системные метрики"""
        with self.lock:
            # CPU и память
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            
            system_data = {
                'timestamp': datetime.now().isoformat(),
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_used_gb': memory.used / (1024**3),
                'memory_available_gb': memory.available / (1024**3)
            }
            
            self.metrics['cpu_usage'].append(system_data)
            self.metrics['memory_usage'].append(system_data)
            
            # Логируем
            self.logger.info(
                f"System: CPU {cpu_percent:.1f}%, "
                f"Memory {memory.percent:.1f}% "
                f"({memory.used / (1024**3):.1f}GB used)"
            )
    
    def get_model_performance(self, model_name: str, hours: int = 24) -> Dict:
        """Возвращает производительность модели за указанный период"""
        with self.lock:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            # Фильтруем данные по времени и модели
            model_predictions = [
                p for p in self.metrics['predictions']
                if p['model_name'] == model_name and
                datetime.fromisoformat(p['timestamp']) > cutoff_time
            ]
            
            if not model_predictions:
                return {
                    'model_name': model_name,
                    'total_predictions': 0,
                    'average_time': 0.0,
                    'success_rate': 0.0,
                    'average_accuracy': 0.0,
                    'average_confidence': 0.0
                }
            
            # Вычисляем метрики
            total_predictions = len(model_predictions)
            successful_predictions = [p for p in model_predictions if p['success']]
            success_rate = len(successful_predictions) / total_predictions if total_predictions > 0 else 0
            
            average_time = np.mean([p['prediction_time'] for p in model_predictions])
            average_accuracy = np.mean([p['accuracy'] for p in successful_predictions]) if successful_predictions else 0
            average_confidence = np.mean([p['confidence'] for p in successful_predictions]) if successful_predictions else 0
            
            return {
                'model_name': model_name,
                'total_predictions': total_predictions,
                'average_time': float(average_time),
                'success_rate': float(success_rate),
                'average_accuracy': float(average_accuracy),
                'average_confidence': float(average_confidence),
                'period_hours': hours
            }
    
    def get_system_health(self) -> Dict:
        """Возвращает состояние системы"""
        with self.lock:
            # Последние системные метрики
            if self.metrics['cpu_usage']:
                latest_cpu = self.metrics['cpu_usage'][-1]
                latest_memory = self.metrics['memory_usage'][-1]
            else:
                latest_cpu = {'cpu_percent': 0}
                latest_memory = {'memory_percent': 0}
            
            # Статистика ошибок за последние 24 часа
            cutoff_time = datetime.now() - timedelta(hours=24)
            recent_errors = [
                e for e in self.errors
                if datetime.fromisoformat(e['timestamp']) > cutoff_time
            ]
            
            # Группируем ошибки по типам
            error_types = defaultdict(int)
            for error in recent_errors:
                error_types[error['error_type']] += 1
            
            return {
                'timestamp': datetime.now().isoformat(),
                'cpu_percent': latest_cpu['cpu_percent'],
                'memory_percent': latest_memory['memory_percent'],
                'total_errors_24h': len(recent_errors),
                'error_types': dict(error_types),
                'system_health': 'healthy' if latest_cpu['cpu_percent'] < 80 and latest_memory['memory_percent'] < 80 else 'warning'
            }
    
    def get_metrics_summary(self, hours: int = 24) -> Dict:
        """Возвращает сводку метрик за указанный период"""
        with self.lock:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            # Фильтруем данные по времени
            recent_predictions = [
                p for p in self.metrics['predictions']
                if datetime.fromisoformat(p['timestamp']) > cutoff_time
            ]
            
            recent_training = [
                t for t in self.metrics['training_time']
                if datetime.fromisoformat(t['timestamp']) > cutoff_time
            ]
            
            # Вычисляем общие метрики
            total_predictions = len(recent_predictions)
            successful_predictions = len([p for p in recent_predictions if p['success']])
            success_rate = successful_predictions / total_predictions if total_predictions > 0 else 0
            
            average_prediction_time = np.mean([p['prediction_time'] for p in recent_predictions]) if recent_predictions else 0
            average_accuracy = np.mean([p['accuracy'] for p in recent_predictions if p['success']]) if recent_predictions else 0
            
            return {
                'period_hours': hours,
                'total_predictions': total_predictions,
                'successful_predictions': successful_predictions,
                'success_rate': float(success_rate),
                'average_prediction_time': float(average_prediction_time),
                'average_accuracy': float(average_accuracy),
                'training_sessions': len(recent_training),
                'timestamp': datetime.now().isoformat()
            }
    
    def save_metrics(self):
        """Сохраняет метрики в файлы"""
        with self.lock:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Сохраняем метрики предсказаний
            predictions_file = os.path.join(
                self.log_dir, "metrics", f"predictions_{timestamp}.json"
            )
            with open(predictions_file, 'w') as f:
                json.dump(list(self.metrics['predictions']), f, indent=2)
            
            # Сохраняем метрики обучения
            training_file = os.path.join(
                self.log_dir, "metrics", f"training_{timestamp}.json"
            )
            with open(training_file, 'w') as f:
                json.dump(list(self.metrics['training_time']), f, indent=2)
            
            # Сохраняем ошибки
            errors_file = os.path.join(
                self.log_dir, "errors", f"errors_{timestamp}.json"
            )
            with open(errors_file, 'w') as f:
                json.dump(list(self.errors), f, indent=2)
            
            self.logger.info(f"Metrics saved to {self.log_dir}")
    
    def cleanup_old_logs(self, days: int = 7):
        """Очищает старые логи"""
        cutoff_time = datetime.now() - timedelta(days=days)
        
        for root, dirs, files in os.walk(self.log_dir):
            for file in files:
                if file.endswith('.json') or file.endswith('.log'):
                    file_path = os.path.join(root, file)
                    file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    
                    if file_time < cutoff_time:
                        try:
                            os.remove(file_path)
                            self.logger.info(f"Removed old log: {file_path}")
                        except Exception as e:
                            self.logger.error(f"Error removing {file_path}: {e}")


# Глобальный экземпляр монитора
ml_monitor = MLMonitor()
