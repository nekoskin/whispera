"""
Anomaly Detector - Детектор аномалий в сетевом трафике
Использует различные ML методы для обнаружения аномалий
"""

import tensorflow as tf
import numpy as np
from typing import List, Tuple, Dict, Optional
import json
import os
import warnings
from datetime import datetime

warnings.filterwarnings('ignore', message='.*Trying to unpickle estimator.*from version.*', category=UserWarning)
warnings.filterwarnings('ignore', message='.*InconsistentVersionWarning.*', category=UserWarning)
try:
    from sklearn.exceptions import InconsistentVersionWarning
    warnings.filterwarnings('ignore', category=InconsistentVersionWarning)
except ImportError:
    pass

from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler


class AnomalyDetector:
    """
    Детектор аномалий в сетевом трафике
    Поддерживает различные методы: Autoencoder, Isolation Forest, One-Class SVM
    """
    
    def __init__(self, method: str = "autoencoder"):
        self.method = method
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.threshold = 0.5
        self.anomaly_rate = 0.0
        
        self.prediction_count = 0
        self.total_prediction_time = 0.0
        self.error_count = 0
        
    def build_autoencoder(self, input_size: int = 100) -> tf.keras.Model:
        """Строит СБАЛАНСИРОВАННЫЙ Autoencoder для production"""
        inputs = tf.keras.layers.Input(shape=(input_size,))
        
        x = tf.keras.layers.Dense(128, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.001))(inputs)
        x = tf.keras.layers.BatchNormalization()(x)
        x = tf.keras.layers.Dropout(0.3)(x)
        
        x = tf.keras.layers.Dense(64, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.001))(x)
        x = tf.keras.layers.BatchNormalization()(x)
        x = tf.keras.layers.Dropout(0.3)(x)
        
        x = tf.keras.layers.Dense(32, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.001))(x)
        x = tf.keras.layers.BatchNormalization()(x)
        x = tf.keras.layers.Dropout(0.2)(x)
        
        encoded = tf.keras.layers.Dense(16, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.001))(x)
        
        x = tf.keras.layers.Dense(32, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.001))(encoded)
        x = tf.keras.layers.BatchNormalization()(x)
        x = tf.keras.layers.Dropout(0.2)(x)
        
        x = tf.keras.layers.Dense(64, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.001))(x)
        x = tf.keras.layers.BatchNormalization()(x)
        x = tf.keras.layers.Dropout(0.3)(x)
        
        x = tf.keras.layers.Dense(128, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.001))(x)
        x = tf.keras.layers.BatchNormalization()(x)
        x = tf.keras.layers.Dropout(0.3)(x)
        
        decoded = tf.keras.layers.Dense(input_size, activation='sigmoid')(x)
        
        autoencoder = tf.keras.Model(inputs, decoded)
        
        return autoencoder
    
    def compile_model(self, input_size: int = 100, learning_rate: float = 0.001):
        """Компилирует модель в зависимости от метода"""
        
        if self.method == "autoencoder":
            self.model = self.build_autoencoder(input_size)
            self.model.compile(
                optimizer=tf.keras.optimizers.Adam(learning_rate=learning_rate),
                loss='mse',
                metrics=['mae']
            )
        elif self.method == "isolation_forest":
            self.model = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
        elif self.method == "one_class_svm":
            self.model = OneClassSVM(
                nu=0.1,
                kernel='rbf',
                gamma='scale'
            )
        else:
            raise ValueError(f"Неизвестный метод: {self.method}")
        
        print(f"Anomaly Detector ({self.method}) скомпилирован")
    
    def train(self, X_train: np.ndarray, epochs: int = 200, batch_size: int = 32) -> Dict:
        """Обучает модель детекции аномалий"""
        
        if self.model is None:
            self.compile_model(X_train.shape[1])
        
        X_scaled = self.scaler.fit_transform(X_train)
        
        if self.method == "autoencoder":
            callbacks = [
                tf.keras.callbacks.EarlyStopping(
                    monitor='val_loss',
                    patience=15,
                    restore_best_weights=True,
                    verbose=1,
                    min_delta=0.001,
                    mode='min'
                ),
                tf.keras.callbacks.ReduceLROnPlateau(
                    monitor='val_loss',
                    factor=0.5,
                    patience=8,
                    min_lr=1e-7,
                    verbose=1,
                    mode='min'
                ),
                tf.keras.callbacks.ModelCheckpoint(
                    filepath=f'best_anomaly_{self.method}_model.h5',
                    monitor='val_loss',
                    save_best_only=True,
                    verbose=1,
                    mode='min'
                )
            ]
            
            history = self.model.fit(
                X_scaled, X_scaled,
                epochs=epochs,
                batch_size=batch_size,
                validation_split=0.2,
                verbose=1,
                callbacks=callbacks
            )
            
            train_pred = self.model.predict(X_scaled, verbose=0)
            train_errors = np.mean(np.square(X_scaled - train_pred), axis=1)
            
            mean_error = np.mean(train_errors)
            std_error = np.std(train_errors)
            self.threshold = mean_error + 1.5 * std_error
            
            print(f"📊 Статистика ошибок: mean={mean_error:.4f}, std={std_error:.4f}")
            print(f"🎯 Установлен порог: {self.threshold:.4f}")
            
            self.is_trained = True
            return {
                'history': {k: [float(v) for v in values] for k, values in history.history.items()}, 
                'threshold': float(self.threshold)
            }
        
        else:
            self.model.fit(X_scaled)
            self.is_trained = True
            return {'method': self.method, 'is_trained': True}
    
    def detect_anomaly(self, packet_data: np.ndarray) -> Tuple[bool, float]:
        """Детектирует аномалию в пакете с мониторингом"""
        import time
        start_time = time.time()
        
        try:
            if not self.is_trained:
                raise ValueError("Модель не обучена")
            
            if len(packet_data.shape) == 1:
                packet_data = packet_data.reshape(1, -1)
            
            packet_scaled = self.scaler.transform(packet_data)
            
            if self.method == "autoencoder":
                reconstruction = self.model.predict(packet_scaled, verbose=0)
                error = np.mean(np.square(packet_scaled - reconstruction))
                is_anomaly = error > self.threshold
                anomaly_score = error / self.threshold
                
            elif self.method == "isolation_forest":
                prediction = self.model.predict(packet_scaled)
                is_anomaly = prediction[0] == -1
                anomaly_score = abs(self.model.score_samples(packet_scaled)[0])
                
            elif self.method == "one_class_svm":
                prediction = self.model.predict(packet_scaled)
                is_anomaly = prediction[0] == -1
                anomaly_score = abs(self.model.score_samples(packet_scaled)[0])
            
            else:
                raise ValueError(f"Неизвестный метод: {self.method}")
            
            self.prediction_count += 1
            self.total_prediction_time += time.time() - start_time
            
            return is_anomaly, anomaly_score
            
        except Exception as e:
            self.error_count += 1
            raise
    
    def batch_detect(self, packets: np.ndarray) -> List[Tuple[bool, float]]:
        """Детектирует аномалии для батча пакетов"""
        if not self.is_trained:
            raise ValueError("Модель не обучена")
        
        packets_scaled = self.scaler.transform(packets)
        results = []
        
        if self.method == "autoencoder":
            reconstructions = self.model.predict(packets_scaled, verbose=0)
            errors = np.mean(np.square(packets_scaled - reconstructions), axis=1)
            
            for error in errors:
                is_anomaly = error > self.threshold
                anomaly_score = error / self.threshold
                results.append((is_anomaly, anomaly_score))
        
        else:
            predictions = self.model.predict(packets_scaled)
            scores = self.model.score_samples(packets_scaled)
            
            for pred, score in zip(predictions, scores):
                is_anomaly = pred == -1
                anomaly_score = abs(score)
                results.append((is_anomaly, anomaly_score))
        
        return results
    
    def update_threshold(self, X_val: np.ndarray, anomaly_rate: float = 0.05):
        """Обновляет порог на основе валидационных данных"""
        if not self.is_trained:
            raise ValueError("Модель не обучена")
        
        X_scaled = self.scaler.transform(X_val)
        
        if self.method == "autoencoder":
            reconstructions = self.model.predict(X_scaled, verbose=0)
            errors = np.mean(np.square(X_scaled - reconstructions), axis=1)
            
            self.threshold = np.percentile(errors, (1 - anomaly_rate) * 100)
            self.anomaly_rate = anomaly_rate
        
        print(f"Порог обновлен: {self.threshold:.4f}, ожидаемая доля аномалий: {anomaly_rate}")
    
    def save_model(self, path: str):
        """Сохраняет модель"""
        if not self.is_trained:
            raise ValueError("Модель не обучена")
        
        os.makedirs(path, exist_ok=True)
        
        if self.method == "autoencoder":
            self.model.save(os.path.join(path, 'anomaly_detector.h5'))
        else:
            import joblib
            joblib.dump(self.model, os.path.join(path, 'anomaly_detector.pkl'))
        
        import joblib
        joblib.dump(self.scaler, os.path.join(path, 'scaler.pkl'))
        
        metadata = {
            'method': self.method,
            'threshold': float(self.threshold),
            'anomaly_rate': float(self.anomaly_rate),
            'is_trained': self.is_trained,
            'last_updated': datetime.now().isoformat()
        }
        
        with open(os.path.join(path, 'metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"Anomaly Detector сохранен в {path}")
    
    def load_model(self, path: str):
        """Загружает модель"""
        metadata_path = os.path.join(path, 'metadata.json')
        
        if not os.path.exists(metadata_path):
            raise FileNotFoundError(f"Метаданные не найдены: {metadata_path}")
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        self.method = metadata['method']
        self.threshold = metadata['threshold']
        self.anomaly_rate = metadata['anomaly_rate']
        self.is_trained = metadata['is_trained']
        
        import joblib
        self.scaler = joblib.load(os.path.join(path, 'scaler.pkl'))
        
        if self.method == "autoencoder":
            model_file = os.path.join(path, 'anomaly_detector.h5')
            
            custom_objects = {}
            
            mse_loss = tf.keras.losses.MeanSquaredError()
            
            try:
                import keras.metrics
                if not hasattr(keras.metrics, 'mse'):
                    keras.metrics.mse = mse_loss
            except Exception as e:
                pass
            
            custom_objects['mse'] = mse_loss
            
            try:
                import keras.saving
                custom_objs_dict = keras.saving.get_custom_objects()
                custom_objs_dict['mse'] = mse_loss
            except:
                pass
            
            mae_metric = tf.keras.metrics.MeanAbsoluteError()
            custom_objects['mae'] = mae_metric
            try:
                import keras.saving
                keras.saving.get_custom_objects()['mae'] = mae_metric
            except:
                pass
            
            try:
                self.model = tf.keras.models.load_model(
                    model_file,
                    custom_objects=custom_objects,
                    compile=False
                )
            except Exception as e:
                error_msg = str(e).lower()
                if "could not locate" in error_msg or "mse" in error_msg:
                    try:
                        import os as os_module
                        old_safe_mode = os_module.environ.get('TF_KERAS_SAFE_MODE', None)
                        os_module.environ['TF_KERAS_SAFE_MODE'] = '0'
                        try:
                            self.model = tf.keras.models.load_model(model_file, compile=False)
                        finally:
                            if old_safe_mode is not None:
                                os_module.environ['TF_KERAS_SAFE_MODE'] = old_safe_mode
                            else:
                                os_module.environ.pop('TF_KERAS_SAFE_MODE', None)
                    except Exception as e2:
                        raise ValueError(
                            f"Не удалось загрузить autoencoder модель. "
                            f"Модель была сохранена с несовместимой версией Keras/TensorFlow. "
                            f"Ошибка: {str(e)}. Попробуйте переобучить модель."
                        ) from e
            
            try:
                if not hasattr(self.model, '_compiled') or not self.model._compiled:
                    self.model.compile(
                        optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
                        loss=tf.keras.losses.MeanSquaredError(),
                        metrics=[tf.keras.metrics.MeanAbsoluteError()]
                    )
            except Exception as compile_error:
                print(f"Предупреждение: не удалось перекомпилировать модель: {compile_error}")
                print("Модель будет использоваться без компиляции (только для inference)")
        else:
            import joblib
            self.model = joblib.load(os.path.join(path, 'anomaly_detector.pkl'))
        
        print(f"Anomaly Detector загружен из {path}")
    
    def get_model_info(self) -> Dict:
        """Возвращает информацию о модели"""
        return {
            'method': self.method,
            'is_trained': self.is_trained,
            'threshold': self.threshold,
            'anomaly_rate': self.anomaly_rate,
            'parameters': self.model.count_params() if hasattr(self.model, 'count_params') else 'N/A'
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
