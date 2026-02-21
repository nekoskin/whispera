"""
Traffic Classifier - Классификатор сетевого трафика
Использует TensorFlow для анализа и классификации пакетов
"""

import tensorflow as tf
import numpy as np
import pandas as pd
from typing import List, Tuple, Dict, Optional
import json
import os
import time
import logging
from datetime import datetime


class TrafficClassifier:
    """
    Классификатор сетевого трафика на основе TensorFlow
    Поддерживает CNN, LSTM и Transformer архитектуры
    """
    
    def __init__(self, model_type: str = "cnn", input_size: int = 100, num_classes: int = 22):
        self.model_type = model_type
        self.input_size = input_size
        self.num_classes = num_classes
        self.model = None
        self.history = None
        self.is_trained = False
        self.accuracy = 0.0
        self.last_updated = None
        self.baseline_model = None
        
        self.prediction_count = 0
        self.total_prediction_time = 0.0
        self.error_count = 0
        
        self.logger = logging.getLogger(f'TrafficClassifier_{model_type}')
        self.logger.setLevel(logging.INFO)
        
    def build_model(self) -> tf.keras.Model:
        """Строит модель в зависимости от типа"""
        
        if self.model_type == "cnn":
            return self._build_cnn_model()
        elif self.model_type == "lstm":
            return self._build_lstm_model()
        elif self.model_type == "transformer":
            return self._build_transformer_model()
        else:
            raise ValueError(f"Неизвестный тип модели: {self.model_type}")
    
    def _build_cnn_model(self) -> tf.keras.Model:
        """Строит СБАЛАНСИРОВАННУЮ CNN модель для production"""
        inputs = tf.keras.layers.Input(shape=(self.input_size,))
        
        x = tf.keras.layers.Reshape((self.input_size, 1))(inputs)
        
        x = tf.keras.layers.Conv1D(
            filters=64,
            kernel_size=7,
            activation='relu',
            padding='same',
            kernel_regularizer=tf.keras.regularizers.l2(0.001)
        )(x)
        x = tf.keras.layers.BatchNormalization()(x)
        x = tf.keras.layers.MaxPooling1D(pool_size=2)(x)
        x = tf.keras.layers.Dropout(0.3)(x)
        
        x = tf.keras.layers.Conv1D(
            filters=128,
            kernel_size=5,
            activation='relu',
            padding='same',
            kernel_regularizer=tf.keras.regularizers.l2(0.001)
        )(x)
        x = tf.keras.layers.BatchNormalization()(x)
        x = tf.keras.layers.MaxPooling1D(pool_size=2)(x)
        x = tf.keras.layers.Dropout(0.4)(x)
        
        x = tf.keras.layers.Conv1D(
            filters=256,
            kernel_size=3, 
            activation='relu',
            padding='same',
            kernel_regularizer=tf.keras.regularizers.l2(0.001)
        )(x)
        x = tf.keras.layers.BatchNormalization()(x)
        x = tf.keras.layers.GlobalAveragePooling1D()(x)
        x = tf.keras.layers.Dropout(0.5)(x)
        
        x = tf.keras.layers.Dense(128, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.001))(x)
        x = tf.keras.layers.BatchNormalization()(x)
        x = tf.keras.layers.Dropout(0.5)(x)
        
        x = tf.keras.layers.Dense(64, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.001))(x)
        x = tf.keras.layers.BatchNormalization()(x)
        x = tf.keras.layers.Dropout(0.4)(x)
        
        outputs = tf.keras.layers.Dense(self.num_classes, activation='softmax')(x)
        
        model = tf.keras.Model(inputs=inputs, outputs=outputs)
        return model
    
    def _build_lstm_model(self) -> tf.keras.Model:
        """Строит PRODUCTION LSTM модель с МАКСИМАЛЬНОЙ регуляризацией против переобучения"""
        inputs = tf.keras.layers.Input(shape=(self.input_size,))
        
        x = tf.keras.layers.Reshape((self.input_size, 1))(inputs)
        
        
        x = tf.keras.layers.LSTM(
            64,
            return_sequences=False,
            dropout=0.3,
            recurrent_dropout=0.3,
            kernel_regularizer=tf.keras.regularizers.l2(0.001),
            recurrent_regularizer=tf.keras.regularizers.l2(0.001)
        )(x)
        x = tf.keras.layers.BatchNormalization()(x)
        x = tf.keras.layers.Dropout(0.4)(x)
        
        x = tf.keras.layers.Dense(128, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.001))(x)
        x = tf.keras.layers.BatchNormalization()(x)
        x = tf.keras.layers.Dropout(0.4)(x)
        
        x = tf.keras.layers.Dense(64, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.001))(x)
        x = tf.keras.layers.Dropout(0.3)(x)
        
        outputs = tf.keras.layers.Dense(self.num_classes, activation='softmax')(x)
        
        model = tf.keras.Model(inputs=inputs, outputs=outputs)
        return model
    
    def _build_transformer_model(self) -> tf.keras.Model:
        """Строит PRODUCTION Transformer модель с МАКСИМАЛЬНОЙ регуляризацией против переобучения"""
        inputs = tf.keras.layers.Input(shape=(self.input_size,))
        
        
        x = tf.keras.layers.Reshape((self.input_size, 1))(inputs)
        x = tf.keras.layers.Dense(16, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.01))(x)
        x = tf.keras.layers.BatchNormalization()(x)
        x = tf.keras.layers.Dropout(0.7)(x)
        
        attention_output = tf.keras.layers.MultiHeadAttention(
            num_heads=4,
            key_dim=16,
            dropout=0.3,
            kernel_regularizer=tf.keras.regularizers.l2(0.001)
        )(x, x)
        
        x = tf.keras.layers.Add()([x, attention_output])
        x = tf.keras.layers.LayerNormalization()(x)
        x = tf.keras.layers.Dropout(0.8)(x)
        
        ffn = tf.keras.layers.Dense(128, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.001))(x)
        ffn = tf.keras.layers.Dropout(0.3)(ffn)
        ffn = tf.keras.layers.Dense(64, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.001))(ffn)
        
        x = tf.keras.layers.Add()([x, ffn])
        x = tf.keras.layers.LayerNormalization()(x)
        x = tf.keras.layers.Dropout(0.8)(x)
        
        x = tf.keras.layers.GlobalAveragePooling1D()(x)
        
        x = tf.keras.layers.Dense(128, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.001))(x)
        x = tf.keras.layers.BatchNormalization()(x)
        x = tf.keras.layers.Dropout(0.4)(x)
        
        x = tf.keras.layers.Dense(64, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.001))(x)
        x = tf.keras.layers.Dropout(0.3)(x)
        
        outputs = tf.keras.layers.Dense(self.num_classes, activation='softmax')(x)
        
        model = tf.keras.Model(inputs=inputs, outputs=outputs)
        return model
    
    def compile_model(self, learning_rate: float = 0.001):
        """Компилирует модель с улучшенным оптимизатором и функцией потерь"""
        if self.model is None:
            self.model = self.build_model()
        
        if self.model_type == "transformer":
            learning_rate = learning_rate * 0.5
            optimizer = tf.keras.optimizers.AdamW(
                learning_rate=learning_rate,
                beta_1=0.9,
                beta_2=0.999,
                epsilon=1e-07,
                weight_decay=0.01
            )
        else:
            optimizer = tf.keras.optimizers.Adam(
                learning_rate=learning_rate,
                beta_1=0.9,
                beta_2=0.999,
                epsilon=1e-07,
                amsgrad=False
            )
        
        loss = tf.keras.losses.SparseCategoricalCrossentropy(
            from_logits=False,
            label_smoothing=0.1
        )
        
        metrics = [
            'accuracy', 
            'sparse_top_k_categorical_accuracy',
            'sparse_categorical_crossentropy',
            'sparse_categorical_accuracy'
        ]
        
        if self.model_type == "transformer":
            metrics.append('sparse_top_3_categorical_accuracy')
        
        self.model.compile(
            optimizer=optimizer,
            loss=loss,
            metrics=metrics
        )
        
        print(f"Модель {self.model_type} скомпилирована")
        print(f"Параметров: {self.model.count_params():,}")
        print(f"Learning rate: {learning_rate}")
        print(f"Label smoothing: 0.1")
        print(f"Оптимизатор: {type(optimizer).__name__}")
    
    def create_baseline_model(self, X_train: np.ndarray, y_train: np.ndarray):
        """Создает простую baseline модель для сравнения"""
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.svm import SVC
        from sklearn.naive_bayes import GaussianNB
        from sklearn.tree import DecisionTreeClassifier
        from sklearn.metrics import accuracy_score
        import time
        
        print("🔧 Создание baseline моделей...")
        
        baseline_models = {}
        
        try:
            print("📊 Обучение Random Forest...")
            start_time = time.time()
            rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, max_depth=10)
            rf.fit(X_train, y_train)
            training_time = time.time() - start_time
            baseline_models['random_forest'] = rf
            print(f"✅ Random Forest обучен за {training_time:.2f}с")
        except Exception as e:
            print(f"❌ Ошибка обучения Random Forest: {e}")
            baseline_models['random_forest'] = None
        
        try:
            print("📊 Обучение Logistic Regression...")
            start_time = time.time()
            lr = LogisticRegression(random_state=42, max_iter=1000, C=1.0)
            lr.fit(X_train, y_train)
            training_time = time.time() - start_time
            baseline_models['logistic_regression'] = lr
            print(f"✅ Logistic Regression обучен за {training_time:.2f}с")
        except Exception as e:
            print(f"❌ Ошибка обучения Logistic Regression: {e}")
            baseline_models['logistic_regression'] = None
        
        try:
            print("📊 Обучение Naive Bayes...")
            start_time = time.time()
            nb = GaussianNB()
            nb.fit(X_train, y_train)
            training_time = time.time() - start_time
            baseline_models['naive_bayes'] = nb
            print(f"✅ Naive Bayes обучен за {training_time:.2f}с")
        except Exception as e:
            print(f"❌ Ошибка обучения Naive Bayes: {e}")
            baseline_models['naive_bayes'] = None
        
        try:
            print("📊 Обучение Decision Tree...")
            start_time = time.time()
            dt = DecisionTreeClassifier(random_state=42, max_depth=10)
            dt.fit(X_train, y_train)
            training_time = time.time() - start_time
            baseline_models['decision_tree'] = dt
            print(f"✅ Decision Tree обучен за {training_time:.2f}с")
        except Exception as e:
            print(f"❌ Ошибка обучения Decision Tree: {e}")
            baseline_models['decision_tree'] = None
        
        if len(X_train) < 5000:
            try:
                print("📊 Обучение SVM...")
                start_time = time.time()
                svm = SVC(random_state=42, probability=True, C=1.0, kernel='rbf')
                svm.fit(X_train, y_train)
                training_time = time.time() - start_time
                baseline_models['svm'] = svm
                print(f"✅ SVM обучен за {training_time:.2f}с")
            except Exception as e:
                print(f"❌ Ошибка обучения SVM: {e}")
                baseline_models['svm'] = None
        else:
            print("⚠️ Пропускаем SVM (слишком много данных)")
            baseline_models['svm'] = None
        
        self.baseline_models = baseline_models
        
        print("✅ Baseline модели созданы")
        return self.baseline_models
    
    def _validate_training_data(self, X_train: np.ndarray, y_train: np.ndarray, 
                               X_val: np.ndarray = None, y_val: np.ndarray = None):
        """ИСПРАВЛЕННАЯ валидация данных для production обучения"""
        
        if np.any(np.isnan(X_train)) or np.any(np.isinf(X_train)):
            raise ValueError("КРИТИЧЕСКАЯ ОШИБКА: Обнаружены NaN или Inf значения в обучающих данных")
        
        if np.any(np.isnan(y_train)) or np.any(np.isinf(y_train)):
            raise ValueError("КРИТИЧЕСКАЯ ОШИБКА: Обнаружены NaN или Inf значения в метках")
        
        if len(X_train) != len(y_train):
            raise ValueError(f"КРИТИЧЕСКАЯ ОШИБКА: Размеры X_train ({len(X_train)}) и y_train ({len(y_train)}) не совпадают")
        
        unique_classes, counts = np.unique(y_train, return_counts=True)
        min_samples_per_class = min(counts)
        if min_samples_per_class < 10:
            raise ValueError(f"КРИТИЧЕСКАЯ ОШИБКА: Недостаточно данных. Минимум 10 образцов на класс, получено {min_samples_per_class}")
        
        data_std = np.std(X_train, axis=0)
        low_variance_features = np.sum(data_std < 0.01)
        if low_variance_features > 50:
            print(f"⚠️ ВНИМАНИЕ: Много признаков с низкой вариативностью ({low_variance_features})")
        
        if X_val is not None and y_val is not None:
            if np.any(np.isnan(X_val)) or np.any(np.isinf(X_val)):
                raise ValueError("КРИТИЧЕСКАЯ ОШИБКА: Обнаружены NaN или Inf значения в валидационных данных")
            if len(X_val) != len(y_val):
                raise ValueError(f"КРИТИЧЕСКАЯ ОШИБКА: Размеры X_val ({len(X_val)}) и y_val ({len(y_val)}) не совпадают")
        
        if len(unique_classes) > self.num_classes:
            raise ValueError(f"КРИТИЧЕСКАЯ ОШИБКА: Количество уникальных классов ({len(unique_classes)}) превышает num_classes ({self.num_classes})")
        
        class_balance = min_samples_per_class / max(counts)
        if class_balance < 0.01:
            print(f"⚠️ ВНИМАНИЕ: Сильный дисбаланс классов (соотношение {class_balance:.2f})")
        
        print(f"✅ ВАЛИДАЦИЯ ПРОЙДЕНА: {len(X_train)} образцов, {len(unique_classes)} классов, баланс {class_balance:.2f}")
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray, 
              X_val: np.ndarray = None, y_val: np.ndarray = None,
              epochs: int = 200, batch_size: int = 32,
              validation_split: float = 0.2, class_weight: dict = None) -> Dict:
        """Обучает модель с валидацией данных и baseline сравнением"""
        
        self._validate_training_data(X_train, y_train, X_val, y_val)
        
        baseline_models = self.create_baseline_model(X_train, y_train)
        
        baseline_results = {}
        for name, model in baseline_models.items():
            if model is not None:
                if X_val is not None:
                    y_pred = model.predict(X_val)
                    from sklearn.metrics import accuracy_score
                    accuracy = accuracy_score(y_val, y_pred)
                else:
                    from sklearn.model_selection import train_test_split
                    X_temp, X_val_temp, y_temp, y_val_temp = train_test_split(
                        X_train, y_train, test_size=0.2, random_state=42
                    )
                    y_pred = model.predict(X_val_temp)
                    from sklearn.metrics import accuracy_score
                    accuracy = accuracy_score(y_val_temp, y_pred)
                
                baseline_results[name] = accuracy
                print(f"📊 Baseline {name}: {accuracy:.3f}")
        
        if self.model is None:
            self.compile_model()
        
        callbacks = [
            tf.keras.callbacks.EarlyStopping(
                monitor='val_accuracy' if X_val is not None else 'accuracy',
                patience=5,
                restore_best_weights=True,
                verbose=1,
                min_delta=0.01,
                mode='max'
            ),
            tf.keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss' if X_val is not None else 'loss',
                factor=0.3,
                patience=3,
                min_lr=1e-7,
                verbose=1,
                cooldown=1,
                mode='min'
            ),
            tf.keras.callbacks.ModelCheckpoint(
                filepath=f'best_{self.model_type}_model.h5',
                monitor='val_accuracy' if X_val is not None else 'accuracy',
                save_best_only=True,
                verbose=1,
                save_weights_only=False,
                mode='max'
            ),
            tf.keras.callbacks.TensorBoard(
                log_dir=f'logs/{self.model_type}',
                histogram_freq=1,
                write_graph=True,
                write_images=True,
                update_freq='epoch'
            ),
            tf.keras.callbacks.LearningRateScheduler(
                lambda epoch: learning_rate * (0.8 ** (epoch // 15)),
                verbose=1
            ),
            tf.keras.callbacks.CSVLogger(
                f'logs/{self.model_type}_training.csv',
                append=False
            )
        ]
        
        if X_val is not None and y_val is not None:
            validation_data = (X_val, y_val)
        else:
            validation_data = None
        
        fit_kwargs = {
            'validation_data': validation_data,
            'validation_split': validation_split if validation_data is None else None,
            'epochs': epochs,
            'batch_size': batch_size,
            'callbacks': callbacks,
            'verbose': 1
        }
        
        if class_weight is not None:
            fit_kwargs['class_weight'] = class_weight
            print(f"✅ Применяем балансировку классов: {class_weight}")
        
        self.history = self.model.fit(
            X_train, y_train,
            **fit_kwargs
        )
        
        self.is_trained = True
        self.last_updated = datetime.now()
        self.accuracy = max(self.history.history['val_accuracy']) if 'val_accuracy' in self.history.history else max(self.history.history['accuracy'])
        
        return {
            'history': {k: [float(v) for v in values] for k, values in self.history.history.items()},
            'accuracy': float(self.accuracy),
            'epochs_trained': len(self.history.history['loss'])
        }
    
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Предсказывает классы и вероятности с улучшенной обработкой ошибок"""
        start_time = time.time()
        
        try:
            if not self.is_trained:
                raise ValueError("Модель не обучена")
            
            if self.model is None:
                raise ValueError("Модель не инициализирована")
            
            if X is None:
                raise ValueError("Входные данные не могут быть None")
            
            if len(X) == 0:
                raise ValueError("Пустые входные данные")
            
            if np.any(np.isnan(X)) or np.any(np.isinf(X)):
                self.logger.warning("Найдены NaN/Inf значения, исправляем...")
                X = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=0.0)
            
            if np.any(X < 0) or np.any(X > 1):
                self.logger.warning("Значения вне диапазона [0,1], нормализуем...")
                min_val = np.min(X)
                max_val = np.max(X)
                if max_val > min_val:
                    X = (X - min_val) / (max_val - min_val)
                else:
                    X = np.full_like(X, 0.5)
            
            X = np.clip(X, 0.001, 0.999)
            
            if len(X.shape) != 2:
                raise ValueError(f"Ожидается 2D массив, получен {len(X.shape)}D")
            
            if X.shape[1] != self.input_size:
                self.logger.warning(f"Неожиданный размер входных данных: {X.shape[1]}, ожидался {self.input_size}")
                if X.shape[1] > self.input_size:
                    X = X[:, :self.input_size]
                    self.logger.info(f"Обрезаны данные до размера {self.input_size}")
                else:
                    padding = np.zeros((X.shape[0], self.input_size - X.shape[1]))
                    X = np.concatenate([X, padding], axis=1)
                    self.logger.info(f"Дополнены данные до размера {self.input_size}")
            
            if np.any(np.isnan(X)) or np.any(np.isinf(X)):
                self.logger.warning("Найдены NaN/Inf значения, заменяем на 0")
                X = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=0.0)
            
            if np.all(X == 0):
                self.logger.warning("Все входные данные равны нулю")
            
            try:
                predictions = self.model.predict(X, verbose=0)
            except Exception as predict_error:
                self.logger.error(f"Ошибка при выполнении предсказания: {predict_error}")
                raise ValueError(f"Ошибка модели: {predict_error}")
            
            if predictions is None or len(predictions) == 0:
                raise ValueError("Модель вернула пустой результат")
            
            if predictions.shape[0] != X.shape[0]:
                raise ValueError(f"Несоответствие размеров: вход {X.shape[0]}, выход {predictions.shape[0]}")
            
            classes = np.argmax(predictions, axis=1)
            probabilities = np.max(predictions, axis=1)
            
            if np.any(np.isnan(classes)) or np.any(np.isinf(classes)):
                raise ValueError("Получены NaN/Inf значения в классах")
            
            if np.any(np.isnan(probabilities)) or np.any(np.isinf(probabilities)):
                raise ValueError("Получены NaN/Inf значения в вероятностях")
            
            if np.any(classes < 0) or np.any(classes >= self.num_classes):
                raise ValueError(f"Классы вне допустимого диапазона [0, {self.num_classes})")
            
            if np.any(probabilities < 0) or np.any(probabilities > 1):
                raise ValueError("Вероятности вне допустимого диапазона [0, 1]")
            
            self.prediction_count += len(X)
            self.total_prediction_time += time.time() - start_time
            
            processing_time = time.time() - start_time
            self.logger.info(f"Предсказание завершено: {len(X)} образцов за {processing_time:.3f}с")
            
            return classes, probabilities
            
        except ValueError as ve:
            self.error_count += 1
            self.logger.error(f"Ошибка валидации: {ve}")
            raise
        except Exception as e:
            self.error_count += 1
            self.logger.error(f"Неожиданная ошибка предсказания: {e}")
            self.logger.error(f"Тип ошибки: {type(e).__name__}")
            raise
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """Оценивает модель на тестовых данных"""
        if not self.is_trained:
            raise ValueError("Модель не обучена")
        
        results = self.model.evaluate(X_test, y_test, verbose=0)
        
        return {
            'loss': results[0],
            'accuracy': results[1]
        }
    
    def save_model(self, path: str):
        """Сохраняет модель"""
        if not self.is_trained:
            raise ValueError("Модель не обучена")
        
        os.makedirs(path, exist_ok=True)
        
        self.model.save(os.path.join(path, 'model.h5'))
        
        metadata = {
            'model_type': self.model_type,
            'input_size': self.input_size,
            'num_classes': self.num_classes,
            'accuracy': self.accuracy,
            'last_updated': self.last_updated.isoformat() if self.last_updated else None,
            'is_trained': self.is_trained
        }
        
        with open(os.path.join(path, 'metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"Модель сохранена в {path}")
    
    def load_model(self, path: str):
        """Загружает модель"""
        model_path = os.path.join(path, 'model.h5')
        metadata_path = os.path.join(path, 'metadata.json')
        
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Модель не найдена: {model_path}")
        
        try:
            os.environ['TF_KERAS_SAFE_MODE'] = '0'
            self.model = tf.keras.models.load_model(model_path, compile=False)
        except (ValueError, TypeError, OSError) as e:
            error_msg = str(e)
            if "bad marshal data" in error_msg.lower() or "unknown type code" in error_msg.lower():
                raise ValueError(
                    f"Модель несовместима с текущей версией Python/TensorFlow. "
                    f"Модель была сохранена с другой версией. Ошибка: {error_msg}"
                )
            elif "could not locate" in error_msg.lower() or "custom" in error_msg.lower():
                try:
                    self.model = tf.keras.models.load_model(model_path, compile=False)
                except Exception as e2:
                    raise ValueError(
                        f"Не удалось загрузить модель из-за несовместимости кастомных объектов. "
                        f"Ошибка: {str(e2)}"
                    )
            else:
                raise ValueError(f"Ошибка загрузки модели: {error_msg}")
        
        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                self.model_type = metadata['model_type']
                self.input_size = metadata['input_size']
                self.num_classes = metadata['num_classes']
                self.accuracy = metadata['accuracy']
                self.is_trained = metadata['is_trained']
                
                if metadata['last_updated']:
                    self.last_updated = datetime.fromisoformat(metadata['last_updated'])
            except Exception as e:
                self.logger.warning(f"Ошибка загрузки метаданных: {e}, используем значения по умолчанию")
                self.is_trained = True
        
        print(f"Модель загружена из {path}")
    
    def get_model_info(self) -> Dict:
        """Возвращает информацию о модели"""
        return {
            'model_type': self.model_type,
            'input_size': self.input_size,
            'num_classes': self.num_classes,
            'is_trained': self.is_trained,
            'accuracy': self.accuracy,
            'last_updated': self.last_updated.isoformat() if self.last_updated else None,
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
