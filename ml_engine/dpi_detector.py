"""
DPI Detector - Детектор Deep Packet Inspection
Использует машинное обучение для обнаружения DPI систем
"""

import tensorflow as tf
import numpy as np
from typing import List, Tuple, Dict, Optional
import json
import os
from datetime import datetime


class DPIDetector:
    """
    Детектор DPI систем на основе машинного обучения
    Классифицирует типы DPI и их методы обнаружения
    """
    
    def __init__(self):
        self.model = None
        self.is_trained = False
        self.accuracy = 0.0
        self.dpi_types = {
            0: "no_dpi",
            1: "simple_dpi", 
            2: "deep_packet_inspection",
            3: "flow_analysis",
            4: "ml_dpi"
        }
        
        # Мониторинг и метрики
        self.prediction_count = 0
        self.total_prediction_time = 0.0
        self.error_count = 0
        
    def build_model(self) -> tf.keras.Model:
        """Строит PRODUCTION модель для детекции DPI с МАКСИМАЛЬНОЙ регуляризацией"""
        model = tf.keras.Sequential([
            # Входной слой с правильной формой
            tf.keras.layers.Input(shape=(100,)),
            
            # PRODUCTION архитектура с агрессивной регуляризацией
            tf.keras.layers.Dense(64, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.01)),  # УМЕНЬШЕНО: Было 256, стало 64
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(0.7),  # УВЕЛИЧЕНО: Было 0.3, стало 0.7
            
            tf.keras.layers.Dense(32, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.01)),  # УМЕНЬШЕНО: Было 128, стало 32
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(0.7),  # УВЕЛИЧЕНО: Было 0.25, стало 0.7
            
            tf.keras.layers.Dense(16, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.01)),  # УМЕНЬШЕНО: Было 64, стало 16
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(0.7),  # УВЕЛИЧЕНО: Было 0.2, стало 0.7
            
            tf.keras.layers.Dense(8, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.01)),  # УМЕНЬШЕНО: Было 32, стало 8
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(0.7),  # УВЕЛИЧЕНО: Было 0.1, стало 0.7
            
            # Выходной слой (5 типов DPI)
            tf.keras.layers.Dense(5, activation='softmax')
        ])
        
        return model
    
    def compile_model(self, learning_rate: float = 0.001):
        """Компилирует модель"""
        if self.model is None:
            self.model = self.build_model()
        
        self.model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=learning_rate),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        print("DPI Detector модель скомпилирована")
        print(f"Параметров: {self.model.count_params():,}")
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray,
              X_val: np.ndarray = None, y_val: np.ndarray = None,
              epochs: int = 200, batch_size: int = 32) -> Dict:
        """Обучает модель детекции DPI"""
        
        if self.model is None:
            self.compile_model()
        
        # УЛУЧШЕННЫЕ callbacks для лучшего обучения
        callbacks = [
            tf.keras.callbacks.EarlyStopping(
                monitor='val_accuracy' if X_val is not None else 'accuracy',
                patience=20,
                restore_best_weights=True,
                verbose=1,
                min_delta=0.001,
                mode='max'
            ),
            tf.keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss' if X_val is not None else 'loss',
                factor=0.5,
                patience=10,
                min_lr=1e-7,
                verbose=1,
                mode='min'
            ),
            tf.keras.callbacks.ModelCheckpoint(
                filepath=f'best_dpi_model.h5',
                monitor='val_accuracy' if X_val is not None else 'accuracy',
                save_best_only=True,
                verbose=1,
                mode='max'
            )
        ]
        
        # Обучение
        validation_data = (X_val, y_val) if X_val is not None else None
        
        history = self.model.fit(
            X_train, y_train,
            validation_data=validation_data,
            validation_split=0.2 if validation_data is None else None,
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callbacks,
            verbose=1
        )
        
        # Обновляем статус
        self.is_trained = True
        self.accuracy = max(history.history['val_accuracy']) if 'val_accuracy' in history.history else max(history.history['accuracy'])
        
        return {
            'history': {k: [float(v) for v in values] for k, values in history.history.items()},
            'accuracy': float(self.accuracy),
            'epochs_trained': len(history.history['loss'])
        }
    
    def detect_dpi(self, packet_data: np.ndarray) -> Tuple[int, float, str]:
        """Детектирует тип DPI в пакете с мониторингом"""
        import time
        start_time = time.time()
        
        try:
            if not self.is_trained:
                raise ValueError("Модель не обучена")
            
            # Подготавливаем данные
            if len(packet_data.shape) == 1:
                packet_data = packet_data.reshape(1, -1)
            
            # Предсказание
            prediction = self.model.predict(packet_data, verbose=0)
            dpi_type = np.argmax(prediction[0])
            confidence = np.max(prediction[0])
            dpi_name = self.dpi_types[dpi_type]
            
            # Обновляем метрики
            self.prediction_count += 1
            self.total_prediction_time += time.time() - start_time
            
            return dpi_type, confidence, dpi_name
            
        except Exception as e:
            self.error_count += 1
            raise
    
    def batch_detect(self, packets: np.ndarray) -> List[Tuple[int, float, str]]:
        """Детектирует DPI для батча пакетов"""
        if not self.is_trained:
            raise ValueError("Модель не обучена")
        
        predictions = self.model.predict(packets, verbose=0)
        results = []
        
        for pred in predictions:
            dpi_type = np.argmax(pred)
            confidence = np.max(pred)
            dpi_name = self.dpi_types[dpi_type]
            results.append((dpi_type, confidence, dpi_name))
        
        return results
    
    def save_model(self, path: str):
        """Сохраняет модель"""
        if not self.is_trained:
            raise ValueError("Модель не обучена")
        
        os.makedirs(path, exist_ok=True)
        
        # Сохраняем модель
        self.model.save(os.path.join(path, 'dpi_detector.h5'))
        
        # Сохраняем метаданные
        metadata = {
            'accuracy': self.accuracy,
            'last_updated': datetime.now().isoformat(),
            'is_trained': self.is_trained,
            'dpi_types': self.dpi_types
        }
        
        with open(os.path.join(path, 'metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"DPI Detector сохранен в {path}")
    
    def load_model(self, path: str):
        """Загружает модель"""
        model_path = os.path.join(path, 'dpi_detector.h5')
        metadata_path = os.path.join(path, 'metadata.json')
        
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Модель не найдена: {model_path}")
        
        # Загружаем модель
        self.model = tf.keras.models.load_model(model_path)
        
        # Загружаем метаданные
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            self.accuracy = metadata['accuracy']
            self.is_trained = metadata['is_trained']
            self.dpi_types = metadata['dpi_types']
        
        print(f"DPI Detector загружен из {path}")
    
    def get_model_info(self) -> Dict:
        """Возвращает информацию о модели"""
        return {
            'is_trained': self.is_trained,
            'accuracy': self.accuracy,
            'dpi_types': self.dpi_types,
            'parameters': self.model.count_params() if self.model else 0
        }
    
    def get_performance_metrics(self) -> Dict:
        """Возвращает метрики производительности"""
        avg_prediction_time = self.total_prediction_time / max(self.prediction_count, 1)
        error_rate = self.error_count / max(self.prediction_count, 1)
        
        return {
            'prediction_count': self.prediction_count,
            'total_prediction_time': self.total_prediction_time,
            'average_prediction_time': avg_prediction_time,
            'error_count': self.error_count,
            'error_rate': error_rate,
            'throughput_per_second': 1.0 / max(avg_prediction_time, 0.001)
        }
