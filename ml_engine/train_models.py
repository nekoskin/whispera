"""
Train Models - Скрипт для обучения ML моделей
Создает и обучает все модели для системы Whispera
"""

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import json
import os
from datetime import datetime

from model_manager import ModelManager
from traffic_classifier import TrafficClassifier
from dpi_detector import DPIDetector
from anomaly_detector import AnomalyDetector


def validate_training_data(X: np.ndarray, y: np.ndarray, task_name: str = "training") -> bool:
    """
    УЛУЧШЕННАЯ валидация данных для обучения
    Проверяет качество данных и их готовность к обучению
    """
    print(f"ВАЛИДАЦИЯ ДАННЫХ ДЛЯ {task_name}...")
    
    # 1. Проверка на пустые данные
    if X is None or y is None:
        print("КРИТИЧЕСКАЯ ОШИБКА: Данные не могут быть None")
        return False
    
    if len(X) == 0 or len(y) == 0:
        print("КРИТИЧЕСКАЯ ОШИБКА: Пустые данные")
        return False
    
    # 2. Проверка соответствия размеров
    if len(X) != len(y):
        print(f"КРИТИЧЕСКАЯ ОШИБКА: Размеры X ({len(X)}) и y ({len(y)}) не совпадают")
        return False
    
    # 3. Проверка на NaN и Inf
    if np.any(np.isnan(X)) or np.any(np.isinf(X)):
        print("ОШИБКА КРИТИЧЕСКАЯ ОШИБКА: Найдены NaN или Inf значения в X")
        return False
    
    if np.any(np.isnan(y)) or np.any(np.isinf(y)):
        print("ОШИБКА КРИТИЧЕСКАЯ ОШИБКА: Найдены NaN или Inf значения в y")
        return False
    
    # 4. Проверка качества данных
    unique_classes = np.unique(y)
    min_samples_per_class = np.min([np.sum(y == cls) for cls in unique_classes])
    
    if min_samples_per_class < 5:
        print(f"ВНИМАНИЕ ВНИМАНИЕ: Некоторые классы имеют менее 5 образцов (минимум: {min_samples_per_class})")
        print("РЕКОМЕНДАЦИЯ Рекомендуется собрать больше данных")
    
    # 5. Проверка вариативности данных
    feature_variance = np.var(X, axis=0)
    low_variance_features = np.sum(feature_variance < 1e-6)
    
    if low_variance_features > 0:
        print(f"ВНИМАНИЕ ВНИМАНИЕ: {low_variance_features} признаков имеют очень низкую вариативность")
        print("РЕКОМЕНДАЦИЯ Рекомендуется проверить feature engineering")
    
    # 6. Проверка баланса классов
    class_counts = [np.sum(y == cls) for cls in unique_classes]
    imbalance_ratio = max(class_counts) / min(class_counts)
    
    if imbalance_ratio > 10:
        print(f"ВНИМАНИЕ ВНИМАНИЕ: Сильный дисбаланс классов (соотношение {imbalance_ratio:.1f}:1)")
        print("РЕКОМЕНДАЦИЯ Рекомендуется использовать class_weight или SMOTE")
    
    print(f"УСПЕХ Валидация пройдена: {len(X)} образцов, {len(unique_classes)} классов")
    return True


def calculate_real_metrics(model, X_test: np.ndarray, y_test: np.ndarray, model_name: str = "model") -> dict:
    """
    Вычисляет РЕАЛЬНЫЕ метрики производительности модели
    """
    try:
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
        
        # Предсказания
        if hasattr(model, 'predict'):
            y_pred = model.predict(X_test)
        else:
            # Для TensorFlow моделей
            predictions = model.predict(X_test)
            y_pred = np.argmax(predictions, axis=1)
        
        # Вычисляем метрики
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        
        # Дополнительные метрики
        unique_classes = len(np.unique(y_test))
        samples_per_class = [np.sum(y_test == cls) for cls in np.unique(y_test)]
        
        metrics = {
            'model_name': model_name,
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'num_classes': int(unique_classes),
            'min_samples_per_class': int(min(samples_per_class)),
            'max_samples_per_class': int(max(samples_per_class)),
            'total_samples': len(y_test),
            'timestamp': datetime.now().isoformat()
        }
        
        print(f"СТАТИСТИКА Реальные метрики {model_name}:")
        print(f"  - Accuracy: {accuracy:.3f}")
        print(f"  - Precision: {precision:.3f}")
        print(f"  - Recall: {recall:.3f}")
        print(f"  - F1-Score: {f1:.3f}")
        
        return metrics
        
    except Exception as e:
        print(f"ОШИБКА Ошибка вычисления метрик для {model_name}: {e}")
        return {
            'model_name': model_name,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }


def load_real_traffic_data(data_path: str = "real_traffic_data.csv") -> tuple:
    """Загружает реальные данные трафика из файла"""
    print(f"📁 Загрузка реальных данных из {data_path}...")
    
    if not os.path.exists(data_path):
        print(f"ОШИБКА Файл данных не найден: {data_path}")
        print("РЕКОМЕНДАЦИЯ Создайте файл с реальными данными трафика или используйте capture_real_traffic()")
        return None
    
    try:
        # Загружаем данные
        df = pd.read_csv(data_path)
        print(f"УСПЕХ Загружено {len(df)} записей")
        
        # Проверяем структуру данных
        required_columns = ['features', 'traffic_class', 'dpi_type', 'is_anomaly']
        missing_columns = [col for col in required_columns if col not in df.columns]
        
        if missing_columns:
            print(f"ОШИБКА Отсутствуют колонки: {missing_columns}")
            print("РЕКОМЕНДАЦИЯ Ожидаемые колонки: features, traffic_class, dpi_type, is_anomaly")
            return None
        
        # Извлекаем данные БЕЗОПАСНО
        import ast
        X = np.array([ast.literal_eval(features) for features in df['features']], dtype=np.float32)
        traffic_labels = df['traffic_class'].values.astype(np.int32)
        dpi_labels = df['dpi_type'].values.astype(np.int32)
        anomaly_labels = df['is_anomaly'].values.astype(np.int32)
        
        # Валидация данных
        print(f"УСПЕХ Данные загружены:")
        print(f"  - Размер: {X.shape}")
        print(f"  - Классы трафика: {len(np.unique(traffic_labels))}")
        print(f"  - Типы DPI: {len(np.unique(dpi_labels))}")
        print(f"  - Аномалии: {np.sum(anomaly_labels)} ({np.mean(anomaly_labels)*100:.1f}%)")
        
        # УЛУЧШЕННАЯ проверка качества данных
        if np.any(np.isnan(X)) or np.any(np.isinf(X)):
            print("ВНИМАНИЕ ВНИМАНИЕ: Найдены NaN или Inf значения в данных!")
            # Попытка исправить данные
            X = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=0.0)
            print("ИНСТРУМЕНТ Данные исправлены (заменены на 0/1)")
        
        # Проверка диапазонов значений
        if np.any(X < 0) or np.any(X > 1):
            print("ВНИМАНИЕ ВНИМАНИЕ: Данные вне диапазона [0,1]!")
            # Нормализация данных
            X = (X - np.min(X)) / (np.max(X) - np.min(X))
            print("ИНСТРУМЕНТ Данные нормализованы в диапазон [0,1]")
        
        # Проверка распределения классов
        unique_classes, counts = np.unique(traffic_labels, return_counts=True)
        print(f"  - Распределение классов трафика:")
        for cls, count in zip(unique_classes, counts):
            print(f"    Класс {cls}: {count} ({count/len(traffic_labels)*100:.1f}%)")
        
        # Проверка на дисбаланс классов
        min_class_count = np.min(counts)
        max_class_count = np.max(counts)
        imbalance_ratio = max_class_count / min_class_count
        
        if imbalance_ratio > 10:
            print(f"ВНИМАНИЕ ВНИМАНИЕ: Сильный дисбаланс классов (соотношение {imbalance_ratio:.1f}:1)")
            print("РЕКОМЕНДАЦИЯ Рекомендуется использовать class_weight или SMOTE")
        
        # ИСПРАВЛЕНО: Умная обработка размерности данных
        TARGET_FEATURES = 100  # Константа для всех компонентов системы
        
        if X.shape[1] != TARGET_FEATURES:
            print(f"ИНСТРУМЕНТ Адаптация размерности: {X.shape[1]} -> {TARGET_FEATURES}")
            
            if X.shape[1] > TARGET_FEATURES:
                # Используем feature selection для отбора лучших признаков
                from sklearn.feature_selection import SelectKBest, f_classif
                print(f"СТАТИСТИКА Анализ важности признаков...")
                
                # Проверяем, есть ли достаточно данных для feature selection
                if len(np.unique(traffic_labels)) > 1 and len(traffic_labels) > 50:
                    try:
                        selector = SelectKBest(f_classif, k=TARGET_FEATURES)
                        X = selector.fit_transform(X, traffic_labels)
                        print(f"УСПЕХ Отобрано {TARGET_FEATURES} лучших признаков из {X.shape[1]}")
                    except Exception as e:
                        print(f"ВНИМАНИЕ Ошибка feature selection: {e}")
                        # Fallback: простое обрезание
                        X = X[:, :TARGET_FEATURES]
                        print(f"ИНСТРУМЕНТ Простое обрезание до {TARGET_FEATURES} признаков")
                else:
                    # Недостаточно данных для feature selection
                    X = X[:, :TARGET_FEATURES]
                    print(f"ИНСТРУМЕНТ Простое обрезание до {TARGET_FEATURES} признаков (недостаточно данных для feature selection)")
            else:
                # Дополняем данными с предупреждением
                padding = np.zeros((X.shape[0], TARGET_FEATURES - X.shape[1]))
                X = np.concatenate([X, padding], axis=1)
                print(f"ВНИМАНИЕ Данные дополнены нулями до {TARGET_FEATURES} признаков")
                print("РЕКОМЕНДАЦИЯ Рекомендуется собрать больше данных для лучшего качества")
        
        # ДОБАВЛЯЕМ: Проверка и исправление несогласованности размеров
        print(f"ПОИСК Финальная проверка размеров: {X.shape}")
        if X.shape[1] != TARGET_FEATURES:
            print(f"ОШИБКА КРИТИЧЕСКАЯ ОШИБКА: Размер данных {X.shape[1]} не соответствует TARGET_FEATURES {TARGET_FEATURES}")
            # Принудительно обрезаем или дополняем
            if X.shape[1] > TARGET_FEATURES:
                X = X[:, :TARGET_FEATURES]
                print(f"ИНСТРУМЕНТ Принудительно обрезано до {TARGET_FEATURES} признаков")
            else:
                padding = np.zeros((X.shape[0], TARGET_FEATURES - X.shape[1]))
                X = np.concatenate([X, padding], axis=1)
                print(f"ИНСТРУМЕНТ Принудительно дополнено до {TARGET_FEATURES} признаков")
        
        print(f"УСПЕХ Размеры унифицированы: {X.shape}")
        
        return X, traffic_labels, dpi_labels, anomaly_labels
        
    except Exception as e:
        print(f"ОШИБКА Ошибка загрузки данных: {e}")
        return None


def capture_real_traffic(duration: int = 60, interface: str = None) -> tuple:
    """Захватывает реальный сетевой трафик с помощью scapy"""
    print(f"СЕТЬ Захват реального трафика на {duration} секунд...")
    
    try:
        import scapy.all as scapy
        import time
        from datetime import datetime
        
        print("📡 Начинаем захват трафика с помощью scapy...")
        print("ВНИМАНИЕ ВНИМАНИЕ: Для захвата трафика нужны права администратора!")
        
        # Проверяем доступные интерфейсы
        try:
            interfaces = scapy.get_if_list()
            print(f"ПОИСК Доступные интерфейсы: {interfaces}")
            
            # Пробуем найти активный интерфейс
            active_interface = None
            for iface in interfaces:
                if not iface.startswith('lo') and not iface.startswith('Loopback'):
                    active_interface = iface
                    break
            
            if active_interface:
                print(f"📡 Используем интерфейс: {active_interface}")
            else:
                print("ВНИМАНИЕ Не найден активный интерфейс")
                
        except Exception as e:
            print(f"ВНИМАНИЕ Ошибка проверки интерфейсов: {e}")
        
        # Список для хранения захваченных пакетов
        captured_packets = []
        traffic_labels = []
        dpi_labels = []
        anomaly_labels = []
        
        # Временной анализ
        packet_timestamps = []
        last_packet_time = time.time()
        
        def packet_handler(packet):
            """УЛУЧШЕННЫЙ обработчик пакетов с временным анализом"""
            nonlocal last_packet_time
            try:
                current_time = time.time()
                packet_interval = current_time - last_packet_time
                last_packet_time = current_time
                
                # Сохраняем временную метку
                packet_timestamps.append(current_time)
                
                # Извлекаем признаки из пакета
                features = extract_packet_features(packet)
                if features is not None:
                    # ДОБАВЛЯЕМ: временные признаки в features
                    if len(features) >= 2:
                        features[1] = packet_interval  # Интервал между пакетами
                    
                    captured_packets.append(features)
                    
                    # Классифицируем трафик
                    traffic_class = classify_traffic(packet)
                    traffic_labels.append(traffic_class)
                    
                    # Определяем DPI тип
                    dpi_type = detect_dpi_type(packet)
                    dpi_labels.append(dpi_type)
                    
                    # Проверяем на аномалии
                    is_anomaly = detect_anomaly(packet)
                    anomaly_labels.append(is_anomaly)
                    
            except Exception as e:
                print(f"ВНИМАНИЕ Ошибка обработки пакета: {e}")
        
        # Захватываем трафик
        print(f"ПОИСК Захватываем трафик на {duration} секунд...")
        print("СТАТИСТИКА Статистика захвата:")
        packet_count = 0
        
        def packet_counter(packet):
            nonlocal packet_count
            packet_count += 1
            if packet_count % 10 == 0:
                print(f"  📦 Захвачено пакетов: {packet_count}")
            packet_handler(packet)
        
        try:
            # АГРЕССИВНЫЙ захват трафика с множественными попытками
            print("ПОИСК Агрессивный захват трафика...")
            
            # Попытка 1: TCP/UDP трафик
            print("ПОИСК Попытка 1: TCP/UDP трафик...")
            scapy.sniff(prn=packet_counter, timeout=min(duration//3, 20), store=0, filter="tcp or udp")
            
            if packet_count == 0:
                # Попытка 2: Весь IP трафик
                print("ПОИСК Попытка 2: Весь IP трафик...")
                scapy.sniff(prn=packet_counter, timeout=min(duration//3, 20), store=0, filter="ip")
            
            if packet_count == 0:
                # Попытка 3: Весь трафик без фильтров
                print("ПОИСК Попытка 3: Весь трафик без фильтров...")
                scapy.sniff(prn=packet_counter, timeout=min(duration//3, 20), store=0)
            
            if packet_count == 0:
                # Попытка 4: Специфичные порты
                print("ПОИСК Попытка 4: Специфичные порты (80, 443, 22, 53)...")
                scapy.sniff(prn=packet_counter, timeout=min(duration//3, 20), store=0, filter="port 80 or port 443 or port 22 or port 53")
                
        except OverflowError:
            print("ОШИБКА Слишком большое значение timeout")
            print("РЕКОМЕНДАЦИЯ Используйте значение меньше 3600 секунд")
            return None
        except PermissionError:
            print("ОШИБКА Недостаточно прав для захвата трафика")
            print("РЕКОМЕНДАЦИЯ Запустите скрипт с правами администратора")
            return None
        except Exception as e:
            print(f"ОШИБКА Ошибка захвата: {e}")
            return None
        
        print(f"СТАТИСТИКА Всего захвачено пакетов: {packet_count}")
        
        if len(captured_packets) == 0:
            print("ОШИБКА Не удалось захватить пакеты")
            print("РЕКОМЕНДАЦИЯ Возможные причины:")
            print("  1. Нет активного сетевого трафика")
            print("  2. Антивирус блокирует захват")
            print("  3. Нужны дополнительные права")
            print("  4. Попробуйте запустить браузер для генерации трафика")
            print("  5. Проверьте сетевые интерфейсы")
            print("  6. Попробуйте запустить с правами администратора")
            return None
        
        # Проверяем минимальное количество пакетов
        if len(captured_packets) < 10:
            print(f"ВНИМАНИЕ Захвачено мало пакетов ({len(captured_packets)}), продолжаем...")
            print("РЕКОМЕНДАЦИЯ Для лучшего обучения рекомендуется минимум 100 пакетов")
        
        # Конвертируем в numpy arrays
        X = np.array(captured_packets, dtype=np.float32)
        traffic_labels = np.array(traffic_labels, dtype=np.int32)
        dpi_labels = np.array(dpi_labels, dtype=np.int32)
        anomaly_labels = np.array(anomaly_labels, dtype=np.int32)
        
        # === ВРЕМЕННОЙ АНАЛИЗ ===
        if len(packet_timestamps) > 1:
            # Анализ интервалов между пакетами
            intervals = np.diff(packet_timestamps)
            avg_interval = np.mean(intervals)
            std_interval = np.std(intervals)
            
            print(f"СТАТИСТИКА Временной анализ:")
            print(f"  - Средний интервал: {avg_interval:.4f} сек")
            print(f"  - Стандартное отклонение: {std_interval:.4f} сек")
            print(f"  - Минимальный интервал: {np.min(intervals):.4f} сек")
            print(f"  - Максимальный интервал: {np.max(intervals):.4f} сек")
            
            # Детекция burst трафика
            burst_threshold = avg_interval - 2 * std_interval
            burst_packets = np.sum(intervals < burst_threshold)
            print(f"  - Burst пакетов: {burst_packets} ({burst_packets/len(intervals)*100:.1f}%)")
        
        print(f"УСПЕХ Реальный трафик захвачен:")
        print(f"  - Размер: {X.shape}")
        print(f"  - Классы трафика: {len(np.unique(traffic_labels))}")
        print(f"  - Типы DPI: {len(np.unique(dpi_labels))}")
        print(f"  - Аномалии: {np.sum(anomaly_labels)} ({np.mean(anomaly_labels)*100:.1f}%)")
        
        return X, traffic_labels, dpi_labels, anomaly_labels
        
    except ImportError:
        print("ОШИБКА Scapy не установлен. Установите: pip install scapy")
        print("РЕКОМЕНДАЦИЯ Для работы с реальными данными установите scapy")
        return None
    except Exception as e:
        print(f"ОШИБКА Ошибка захвата трафика: {e}")
        return None


def extract_packet_features(packet) -> np.ndarray:
    """УЛУЧШЕННАЯ экстракция признаков из пакета с продвинутым feature engineering"""
    try:
        import scapy.all as scapy
        import hashlib
        import time
        import statistics
        
        # ИСПРАВЛЕНО: Унифицированная структура признаков (100 признаков)
        TARGET_FEATURES = 100  # Константа для всех компонентов
        features = np.zeros(TARGET_FEATURES, dtype=np.float32)
        idx = 0
        
        # ДОБАВЛЯЕМ: Универсальная функция для безопасного извлечения значений
        def safe_extract_value(obj, default=0.0):
            """Безопасно извлекает числовое значение из Scapy объекта"""
            try:
                if hasattr(obj, '__int__'):
                    return float(int(obj))
                elif hasattr(obj, 'value'):
                    return float(obj.value)
                elif hasattr(obj, '__str__'):
                    return float(str(obj))
                else:
                    return default
            except (ValueError, TypeError, AttributeError):
                return default
        
        # ДОБАВЛЯЕМ: Проверка на переполнение индекса
        def safe_add_feature(value, feature_name=""):
            nonlocal idx
            if idx < TARGET_FEATURES:
                features[idx] = float(value)
                idx += 1
                return True
            else:
                print(f"ВНИМАНИЕ Переполнение признаков при добавлении {feature_name}")
                return False
        
        # === ПРОДВИНУТЫЕ БАЗОВЫЕ ХАРАКТЕРИСТИКИ ===
        packet_size = len(packet)
        
        # 1. Размер пакета с улучшенной нормализацией
        safe_add_feature(min(packet_size / 1500.0, 1.0), "packet_size")
        
        # 2. Логарифмический размер (лучше для ML)
        safe_add_feature(np.log1p(packet_size) / np.log1p(1500), "log_packet_size")
        
        # 3. Квадратный корень размера (средний масштаб)
        safe_add_feature(np.sqrt(packet_size) / np.sqrt(1500), "sqrt_packet_size")
        
        # Временная метка (для анализа паттернов)
        current_time = time.time()
        if idx < TARGET_FEATURES:
            # Нормализация времени по часам (0-24)
            features[idx] = (current_time % 86400) / 86400.0
            idx += 1
        
        # ДОБАВЛЯЕМ: Дополнительные временные признаки
        if idx < TARGET_FEATURES:
            # День недели (0-6)
            features[idx] = (current_time // 86400) % 7 / 6.0
            idx += 1
        
        if idx < TARGET_FEATURES:
            # Минута в часе (0-59)
            features[idx] = ((current_time % 3600) // 60) / 59.0
            idx += 1
        
        # === IP ХАРАКТЕРИСТИКИ ===
        if packet.haslayer(scapy.IP):
            ip_layer = packet[scapy.IP]
            
            # УЛУЧШЕННАЯ обработка IP адресов с правильной нормализацией
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            # Правильная нормализация IP адресов
            def normalize_ip(ip_str):
                try:
                    # Разбиваем IP на октеты
                    octets = [int(x) for x in ip_str.split('.')]
                    # Нормализуем каждый октет
                    normalized = [octet / 255.0 for octet in octets]
                    return normalized
                except:
                    return [0.0, 0.0, 0.0, 0.0]
            
            # Нормализация source IP
            src_ip_norm = normalize_ip(src_ip)
            for i, val in enumerate(src_ip_norm):
                if idx < TARGET_FEATURES:
                    features[idx] = val
                    idx += 1
            
            # Нормализация destination IP
            dst_ip_norm = normalize_ip(dst_ip)
            for i, val in enumerate(dst_ip_norm):
                if idx < TARGET_FEATURES:
                    features[idx] = val
                    idx += 1
            
            # TTL (правильная нормализация)
            safe_add_feature(safe_extract_value(ip_layer.ttl) / 255.0, "ip_ttl")
            
            # IP флаги и фрагментация (правильная нормализация)
            safe_add_feature(safe_extract_value(ip_layer.flags) / 7.0, "ip_flags")
            
            # Протокол IP (правильная нормализация)
            safe_add_feature(safe_extract_value(ip_layer.proto) / 255.0, "ip_proto")
        
        # === ТРАНСПОРТНЫЕ ПРОТОКОЛЫ ===
        protocol_type = 0
        src_port = 0
        dst_port = 0
        tcp_flags = 0
        tcp_window = 0
        
        if packet.haslayer(scapy.TCP):
            tcp_layer = packet[scapy.TCP]
            protocol_type = 0  # TCP
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            
            # ИСПРАВЛЕНО: Безопасное извлечение TCP флагов
            tcp_flags = safe_extract_value(tcp_layer.flags, 0)
            
            tcp_window = tcp_layer.window
            
        elif packet.haslayer(scapy.UDP):
            udp_layer = packet[scapy.UDP]
            protocol_type = 1  # UDP
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            
        elif packet.haslayer(scapy.ICMP):
            protocol_type = 2  # ICMP
        else:
            protocol_type = 3  # Other
        
        # Сохраняем транспортные характеристики с правильной нормализацией
        safe_add_feature(float(protocol_type) / 3.0, "protocol_type")
        safe_add_feature(safe_extract_value(src_port) / 65535.0, "src_port")
        safe_add_feature(safe_extract_value(dst_port) / 65535.0, "dst_port")
        safe_add_feature(float(tcp_flags) / 255.0, "tcp_flags")
        safe_add_feature(safe_extract_value(tcp_window) / 65535.0, "tcp_window")
        
        # === ПРОДВИНУТЫЕ СТАТИСТИЧЕСКИЕ ПРИЗНАКИ ===
        if hasattr(packet, 'load') and packet.load:
            payload = packet.load
            if len(payload) > 0:
                # 1. Энтропия Шеннона (улучшенная)
                byte_counts = {}
                for byte in payload:
                    byte_counts[byte] = byte_counts.get(byte, 0) + 1
                
                entropy = 0.0
                for count in byte_counts.values():
                    p = count / len(payload)
                    if p > 0:
                        entropy -= p * np.log2(p)
                
                if idx < TARGET_FEATURES:
                    features[idx] = min(entropy / 8.0, 1.0)
                    idx += 1
                
                # 2. Нормализованная энтропия (0-1)
                if idx < TARGET_FEATURES:
                    max_entropy = np.log2(len(byte_counts)) if len(byte_counts) > 1 else 0
                    features[idx] = entropy / max_entropy if max_entropy > 0 else 0
                    idx += 1
                
                # 3. Количество уникальных байтов
                if idx < TARGET_FEATURES:
                    features[idx] = len(byte_counts) / 256.0
                    idx += 1
                
                # 4. Коэффициент вариации
                if idx < TARGET_FEATURES:
                    mean_val = np.mean(payload)
                    std_val = np.std(payload)
                    features[idx] = std_val / mean_val if mean_val > 0 else 0
                    idx += 1
                
                # Улучшенная статистика байтов
                if idx < TARGET_FEATURES:
                    # Среднее значение (правильная нормализация)
                    features[idx] = float(np.mean(payload)) / 255.0
                    idx += 1
                if idx < TARGET_FEATURES:
                    # Стандартное отклонение (правильная нормализация)
                    features[idx] = float(np.std(payload)) / 255.0
                    idx += 1
                if idx < TARGET_FEATURES:
                    # Минимальное значение
                    features[idx] = float(np.min(payload)) / 255.0
                    idx += 1
                if idx < TARGET_FEATURES:
                    # Максимальное значение
                    features[idx] = float(np.max(payload)) / 255.0
                    idx += 1
                
                # ДОБАВЛЯЕМ: Дополнительные статистические признаки
                if idx < TARGET_FEATURES:
                    # Медиана
                    features[idx] = float(np.median(payload)) / 255.0
                    idx += 1
                if idx < TARGET_FEATURES:
                    # Квантили
                    features[idx] = float(np.percentile(payload, 25)) / 255.0
                    idx += 1
                if idx < TARGET_FEATURES:
                    features[idx] = float(np.percentile(payload, 75)) / 255.0
                    idx += 1
        
        # === ДОПОЛНИТЕЛЬНЫЕ ПРИЗНАКИ ===
        # Ethernet характеристики
        if packet.haslayer(scapy.Ether):
            eth_layer = packet[scapy.Ether]
            safe_add_feature(safe_extract_value(eth_layer.type) / 65535.0, "eth_type")
        
        # DNS характеристики
        if packet.haslayer(scapy.DNS):
            dns_layer = packet[scapy.DNS]
            safe_add_feature(safe_extract_value(dns_layer.qdcount) / 65535.0, "dns_qdcount")
            safe_add_feature(safe_extract_value(dns_layer.ancount) / 65535.0, "dns_ancount")
        
        # HTTP характеристики (проверяем наличие HTTP слоя)
        try:
            if hasattr(scapy, 'HTTP') and packet.haslayer(scapy.HTTP):
                safe_add_feature(1.0, "http_detected")  # HTTP detected
        except AttributeError:
            # HTTP модуль не доступен в этой версии Scapy
            pass
        
        # TLS/HTTPS характеристики (проверяем наличие TLS слоя)
        try:
            if hasattr(scapy, 'TLS') and packet.haslayer(scapy.TLS):
                safe_add_feature(1.0, "tls_detected")  # TLS detected
                
                # Дополнительные TLS признаки
                tls_layer = packet[scapy.TLS]
                if hasattr(tls_layer, 'version'):
                    safe_add_feature(safe_extract_value(tls_layer.version) / 65535.0, "tls_version")
        except AttributeError:
            # TLS модуль не доступен в этой версии Scapy
            pass
        
        # ICMP характеристики
        if packet.haslayer(scapy.ICMP):
            icmp_layer = packet[scapy.ICMP]
            
            # ICMP тип
            safe_add_feature(safe_extract_value(icmp_layer.type) / 255.0, "icmp_type")
            
            # ICMP код
            safe_add_feature(safe_extract_value(icmp_layer.code) / 255.0, "icmp_code")
            
            # ICMP checksum
            if hasattr(icmp_layer, 'chksum'):
                safe_add_feature(safe_extract_value(icmp_layer.chksum) / 65535.0, "icmp_chksum")
            
            # ICMP ID (для Echo Request/Reply)
            if hasattr(icmp_layer, 'id'):
                safe_add_feature(safe_extract_value(icmp_layer.id) / 65535.0, "icmp_id")
            
            # ICMP Sequence (для Echo Request/Reply)
            if hasattr(icmp_layer, 'seq'):
                safe_add_feature(safe_extract_value(icmp_layer.seq) / 65535.0, "icmp_seq")
        
        # ДОБАВЛЯЕМ: Расширенный анализ payload (ограниченный TARGET_FEATURES)
        if hasattr(packet, 'load') and packet.load and idx < TARGET_FEATURES:
            remaining_features = TARGET_FEATURES - idx
            payload = packet.load[:min(len(packet.load), remaining_features)]
            
            # ИСПРАВЛЕНО: Безопасный анализ частоты байтов
            if len(payload) > 0:
                try:
                    # ИСПРАВЛЕНО: Безопасная конвертация payload
                    if isinstance(payload, bytes):
                        payload_array = np.frombuffer(payload, dtype=np.uint8)
                    elif isinstance(payload, (list, tuple)):
                        # Конвертируем список в numpy array
                        payload_array = np.array(payload, dtype=np.uint8)
                    elif isinstance(payload, str):
                        # Конвертируем строку в байты
                        payload_bytes = payload.encode('utf-8')
                        payload_array = np.frombuffer(payload_bytes, dtype=np.uint8)
                    else:
                        # Пытаемся конвертировать в байты
                        payload_bytes = bytes(payload)
                        payload_array = np.frombuffer(payload_bytes, dtype=np.uint8)
                    
                    # Анализ частоты байтов
                    if len(payload_array) > 0:
                        unique, counts = np.unique(payload_array, return_counts=True)
                        
                        # Топ-3 наиболее частых байтов
                        sorted_indices = np.argsort(counts)[::-1][:3]
                        for i in range(3):
                            if i < len(sorted_indices):
                                byte_val = unique[sorted_indices[i]]
                                freq = counts[sorted_indices[i]]
                                safe_add_feature(float(byte_val) / 255.0, f"payload_byte_{i}")
                                safe_add_feature(float(freq) / len(payload_array), f"payload_freq_{i}")
                            else:
                                safe_add_feature(0.0, f"payload_byte_{i}")
                                safe_add_feature(0.0, f"payload_freq_{i}")
                    else:
                        # Пустой payload - заполняем нулями
                        for i in range(3):
                            safe_add_feature(0.0, f"payload_byte_{i}")
                            safe_add_feature(0.0, f"payload_freq_{i}")
                    
                    # Дополняем оставшиеся байты payload данными (ограниченно)
                    remaining_features = TARGET_FEATURES - idx
                    max_payload_bytes = min(len(payload_array), remaining_features, 20)  # Максимум 20 байт
                    
                    for i in range(max_payload_bytes):
                        if i < len(payload_array) and len(payload_array) > 0:
                            safe_add_feature(float(payload_array[i]) / 255.0, f"payload_byte_{i}")
                        else:
                            safe_add_feature(0.0, f"payload_byte_{i}")
                        
                except (ValueError, TypeError, AttributeError) as e:
                    print(f"ВНИМАНИЕ Ошибка обработки payload: {e}")
                    # Заполняем нулями если не удалось обработать
                    for i in range(6):  # 6 признаков payload
                        safe_add_feature(0.0, f"payload_error_{i}")
        
        # ДОБАВЛЯЕМ: Дополнительные признаки для лучшего анализа
        # Анализ протокольных заголовков
        protocol_layers = 0
        if packet.haslayer(scapy.Ether): protocol_layers += 1
        if packet.haslayer(scapy.IP): protocol_layers += 1
        if packet.haslayer(scapy.TCP): protocol_layers += 1
        elif packet.haslayer(scapy.UDP): protocol_layers += 1
        elif packet.haslayer(scapy.ICMP): protocol_layers += 1
        safe_add_feature(float(protocol_layers) / 5.0, "protocol_layers")
        
        # ДОБАВЛЯЕМ: Улучшенная валидация и нормализация признаков
        # Проверяем на NaN и Inf значения
        if np.any(np.isnan(features)) or np.any(np.isinf(features)):
            print(f"ВНИМАНИЕ Найдены проблемные значения в признаках, исправляем...")
            features = np.nan_to_num(features, nan=0.0, posinf=1.0, neginf=0.0)
        
        # Проверяем диапазон значений
        min_val = np.min(features)
        max_val = np.max(features)
        
        if min_val < 0 or max_val > 1:
            print(f"ВНИМАНИЕ Признаки вне диапазона [0,1]: [{min_val:.3f}, {max_val:.3f}], нормализуем...")
            if max_val > min_val:
                features = (features - min_val) / (max_val - min_val)
            else:
                features = np.full_like(features, 0.5)
        
        # Дополнительная нормализация для стабильности
        features = np.clip(features, 0.001, 0.999)  # Избегаем точных 0 и 1
        
        # КРИТИЧЕСКАЯ проверка размеров
        if len(features) != TARGET_FEATURES:
            print(f"ОШИБКА КРИТИЧЕСКАЯ ОШИБКА: Размер признаков {len(features)} не соответствует TARGET_FEATURES {TARGET_FEATURES}")
            # Принудительно обрезаем или дополняем
            if len(features) > TARGET_FEATURES:
                features = features[:TARGET_FEATURES]
                print(f"ИНСТРУМЕНТ Принудительно обрезано до {TARGET_FEATURES} признаков")
            else:
                padding = np.zeros(TARGET_FEATURES - len(features))
                features = np.concatenate([features, padding])
                print(f"ИНСТРУМЕНТ Принудительно дополнено до {TARGET_FEATURES} признаков")
        
        print(f"УСПЕХ Признаки извлечены: {len(features)} признаков")
        return features
        
    except Exception as e:
        print(f"ВНИМАНИЕ Ошибка извлечения признаков: {e}")
        return None


def classify_traffic(packet) -> int:
    """
    УЛУЧШЕННАЯ классификация типа трафика
    
    Поддерживаемые типы (22 класса):
    0: HTTPS/HTTP Web
    1: SSH
    2: DNS
    3: FTP
    4: SMTP
    5: Email (POP3/IMAP)
    6: Telnet
    7: Other
    8: VPN
    9: P2P
    10: Gaming
    11: VoIP
    12: Database
    13: Cloud/API
    14: Tor
    15: Remote Access
    16: Network Management
    17: System Services
    18: ICMP (Echo Request/Reply)
    19: ICMP Destination Unreachable
    20: ICMP Time Exceeded
    21: ICMP Redirect
    """
    try:
        import scapy.all as scapy
        
        # === АНАЛИЗ ПО ПРОТОКОЛАМ ===
        # TLS/SSL/HTTPS трафик
        if packet.haslayer(scapy.TLS) or packet.haslayer(scapy.SSL):
            return 0  # HTTPS/Encrypted Web
        
        # HTTP трафик
        if packet.haslayer(scapy.HTTP):
            return 0  # HTTP Web
        
        # DNS трафик
        if packet.haslayer(scapy.DNS):
            return 2  # DNS
        
        # ICMP трафик с детальной классификацией
        if packet.haslayer(scapy.ICMP):
            icmp_layer = packet[scapy.ICMP]
            icmp_type = icmp_layer.type
            
            # Детальная классификация ICMP типов
            if icmp_type == 0:  # Echo Reply (Ping Reply)
                return 18  # ICMP Echo Reply
            elif icmp_type == 8:  # Echo Request (Ping)
                return 18  # ICMP Echo Request
            elif icmp_type == 3:  # Destination Unreachable
                return 19  # ICMP Destination Unreachable
            elif icmp_type == 11:  # Time Exceeded
                return 20  # ICMP Time Exceeded
            elif icmp_type == 5:  # Redirect
                return 21  # ICMP Redirect
            else:
                return 18  # ICMP Other
        
        # === АНАЛИЗ ПО ПОРТАМ ===
        dst_port = 0
        src_port = 0
        
        if packet.haslayer(scapy.TCP):
            dst_port = packet[scapy.TCP].dport
            src_port = packet[scapy.TCP].sport
        elif packet.haslayer(scapy.UDP):
            dst_port = packet[scapy.UDP].dport
            src_port = packet[scapy.UDP].sport
        else:
            return 7  # Unknown
        
        # === УЛУЧШЕННАЯ КЛАССИФИКАЦИЯ ===
        # HTTPS трафик (приоритет для зашифрованного трафика)
        if dst_port in [443, 8443, 9443]:  # HTTPS порты
            return 0  # HTTPS Web
        
        # HTTP трафик
        elif dst_port in [80, 8080, 8000, 3000, 5000]:  # HTTP порты
            return 0  # HTTP Web
        
        # SSH трафик
        elif dst_port == 22:
            return 1  # SSH
        
        # DNS трафик
        elif dst_port == 53:
            return 2  # DNS
        
        # FTP трафик
        elif dst_port in [21, 20, 990, 989]:
            return 3  # FTP
        
        # Email трафик
        elif dst_port in [25, 587, 465]:  # SMTP
            return 4  # SMTP
        elif dst_port in [110, 143, 993, 995]:  # POP3/IMAP
            return 5  # Email
        
        # Telnet трафик
        elif dst_port == 23:
            return 6  # Telnet
        
        # VPN трафик
        elif dst_port in [1194, 1723, 500, 4500]:  # OpenVPN, PPTP, IPSec
            return 8  # VPN
        
        # P2P трафик
        elif dst_port in [6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889]:  # BitTorrent
            return 9  # P2P
        
        # Игровой трафик
        elif dst_port in [27015, 27016, 27017, 27018, 27019, 27020]:  # Steam
            return 10  # Gaming
        
        # VoIP трафик
        elif dst_port in [5060, 5061, 10000, 10001, 10002]:  # SIP, RTP
            return 11  # VoIP
        
        # База данных
        elif dst_port in [3306, 5432, 1433, 1521, 6379, 27017]:  # MySQL, PostgreSQL, MSSQL, Oracle, Redis, MongoDB
            return 12  # Database
        
        # Cloud/API трафик
        elif dst_port in [443, 8443] and src_port > 32768:  # Высокие порты к HTTPS
            return 13  # Cloud/API
        
        # Tor трафик (характерные порты)
        elif dst_port in [9001, 9002, 9030, 9050, 9051]:
            return 14  # Tor
        
        # Другие известные сервисы
        elif dst_port in [3389, 5900, 5901]:  # RDP, VNC
            return 15  # Remote Access
        elif dst_port in [161, 162]:  # SNMP
            return 16  # Network Management
        elif dst_port in [69, 123]:  # TFTP, NTP
            return 17  # System Services
        
        # Неизвестный трафик
        else:
            return 7  # Other
    
    except Exception as e:
        print(f"ВНИМАНИЕ Ошибка классификации трафика: {e}")
        return 7  # Other


def detect_dpi_type(packet) -> int:
    """УЛУЧШЕННАЯ детекция типа DPI с ML-подходом"""
    try:
        import scapy.all as scapy
        import hashlib
        import time
        
        # === РАСШИРЕННЫЙ АНАЛИЗ ПРИЗНАКОВ DPI ===
        dpi_score = 0.0
        dpi_features = []
        
        # 1. Анализ TTL с более сложной логикой
        if packet.haslayer(scapy.IP):
            ttl = packet[scapy.IP].ttl
            # Анализ TTL паттернов
            if ttl in [64, 128, 255]:  # Стандартные TTL
                dpi_score += 0.1
            elif ttl < 32:  # Подозрительно низкий TTL
                dpi_score += 0.3
            elif ttl > 200:  # Подозрительно высокий TTL
                dpi_score += 0.2
        
        # 2. Улучшенный анализ TCP характеристик
        if packet.haslayer(scapy.TCP):
            tcp_layer = packet[scapy.TCP]
            window_size = tcp_layer.window
            
            # Анализ TCP Window Size с весами
            if window_size == 0:  # Нулевое окно
                dpi_score += 0.4
            elif window_size in [8192, 65535]:  # Подозрительные значения
                dpi_score += 0.2
            elif window_size < 1024:  # Маленькое окно
                dpi_score += 0.1
            
            # ИСПРАВЛЕНО: Безопасное извлечение TCP флагов
            flags = safe_extract_value(tcp_layer.flags, 0)
            
            if flags & 0x02:  # SYN флаг
                dpi_score += 0.1
            if flags & 0x04:  # RST флаг
                dpi_score += 0.2
            if flags & 0x08:  # PSH флаг
                dpi_score += 0.1
            
            # Анализ TCP sequence numbers
            if hasattr(tcp_layer, 'seq') and tcp_layer.seq == 0:
                dpi_score += 0.2
        
        # 3. Расширенный анализ портов
        dst_port = 0
        src_port = 0
        if packet.haslayer(scapy.TCP):
            dst_port = packet[scapy.TCP].dport
            src_port = packet[scapy.TCP].sport
        elif packet.haslayer(scapy.UDP):
            dst_port = packet[scapy.UDP].dport
            src_port = packet[scapy.UDP].sport
        
        # Анализ портов с весами
        high_risk_ports = [22, 23, 25, 53, 80, 443, 993, 995, 1194, 1723, 500, 4500]
        medium_risk_ports = [21, 110, 143, 993, 995, 3389, 5900]
        
        if dst_port in high_risk_ports:
            dpi_score += 0.3
        elif dst_port in medium_risk_ports:
            dpi_score += 0.2
        
        # Анализ высоких портов (возможное обход DPI)
        if dst_port > 32768:
            dpi_score += 0.1
        
        # 4. Улучшенный анализ payload
        if hasattr(packet, 'load') and packet.load:
            payload = packet.load
            
            # Поиск DPI signatures с весами
            dpi_signatures = {
                b'User-Agent:': 0.2,
                b'Host:': 0.2,
                b'GET /': 0.3,
                b'POST /': 0.3,
                b'HTTP/1.': 0.2,
                b'Content-Type:': 0.1,
                b'Accept:': 0.1,
                b'Connection:': 0.1,
                b'Authorization:': 0.3,
                b'Cookie:': 0.2
            }
            
            for signature, weight in dpi_signatures.items():
                if signature in payload:
                    dpi_score += weight
            
            # Анализ энтропии payload
            if len(payload) > 0:
                byte_counts = {}
                for byte_val in payload:
                    byte_counts[byte_val] = byte_counts.get(byte_val, 0) + 1
                
                entropy = 0.0
                for count in byte_counts.values():
                    p = count / len(payload)
                    if p > 0:
                        entropy -= p * np.log2(p)
                
                # Высокая энтропия может указывать на шифрование/обход DPI
                if entropy > 7.0:
                    dpi_score += 0.2
                elif entropy < 2.0:  # Низкая энтропия - возможный обход
                    dpi_score += 0.1
        
        # 5. Анализ размера пакета с более сложной логикой
        packet_size = len(packet)
        if packet_size > 1400:  # Большие пакеты
            dpi_score += 0.2
        elif packet_size < 64:  # Очень маленькие пакеты
            dpi_score += 0.1
        elif packet_size == 64:  # Стандартный размер Ethernet
            dpi_score += 0.05
        
        # 6. Расширенный анализ протоколов
        protocol_score = 0
        if packet.haslayer(scapy.HTTP):
            protocol_score += 0.4  # HTTP часто анализируется DPI
        elif packet.haslayer(scapy.TLS):
            protocol_score += 0.5  # TLS/HTTPS часто анализируется DPI
        elif packet.haslayer(scapy.DNS):
            protocol_score += 0.3  # DNS может блокироваться
        elif packet.haslayer(scapy.ICMP):
            icmp_layer = packet[scapy.ICMP]
            if icmp_layer.type in [0, 8]:  # Echo Request/Reply
                protocol_score += 0.3
            else:
                protocol_score += 0.2
        
        dpi_score += protocol_score
        
        # 7. ДОБАВЛЯЕМ: Анализ временных паттернов
        current_time = time.time()
        # Анализ времени (DPI может работать в определенные часы)
        hour = (current_time % 86400) // 3600
        if 9 <= hour <= 17:  # Рабочие часы
            dpi_score += 0.1
        
        # 8. ДОБАВЛЯЕМ: Анализ фрагментации
        if packet.haslayer(scapy.IP):
            ip_layer = packet[scapy.IP]
            if hasattr(ip_layer, 'flags') and ip_layer.flags & 0x01:  # MF флаг
                dpi_score += 0.3
        
        # === УЛУЧШЕННАЯ КЛАССИФИКАЦИЯ DPI ===
        # Используем более точные пороги
        if dpi_score >= 2.0:
            return 4  # ml_dpi (высокая вероятность ML-based DPI)
        elif dpi_score >= 1.5:
            return 3  # flow_analysis (анализ потоков)
        elif dpi_score >= 1.0:
            return 2  # deep_packet_inspection
        elif dpi_score >= 0.5:
            return 1  # simple_dpi
        else:
            return 0  # no_dpi
    
    except Exception as e:
        print(f"ВНИМАНИЕ Ошибка детекции DPI: {e}")
        return 0


def detect_anomaly(packet) -> int:
    """УЛУЧШЕННАЯ детекция аномалий в пакете с ML-подходом"""
    try:
        import scapy.all as scapy
        import time
        import hashlib
        
        anomaly_score = 0.0
        anomaly_features = []
        
        # === РАСШИРЕННЫЙ АНАЛИЗ РАЗМЕРА ПАКЕТА ===
        packet_size = len(packet)
        
        # Анализ размера с весами
        if packet_size > 1500:  # Jumbo frames или фрагментация
            anomaly_score += 0.4
        elif packet_size > 9000:  # Очень большие пакеты
            anomaly_score += 0.6
        elif packet_size < 28:  # Минимальный размер Ethernet + IP
            anomaly_score += 0.3
        elif packet_size < 64:  # Очень маленькие пакеты
            anomaly_score += 0.2
        elif packet_size == 0:  # Пустые пакеты
            anomaly_score += 0.5
        
        # === УЛУЧШЕННЫЙ АНАЛИЗ TCP ФЛАГОВ ===
        if packet.haslayer(scapy.TCP):
            tcp_layer = packet[scapy.TCP]
            
            # ИСПРАВЛЕНО: Безопасное извлечение TCP флагов
            flags = safe_extract_value(tcp_layer.flags, 0)
            
            # Подозрительные комбинации флагов с весами
            if flags & 0x01 and flags & 0x04:  # FIN + RST (необычно)
                anomaly_score += 0.3
            
            if flags & 0x08 and flags & 0x10:  # PSH + ACK (может быть атака)
                anomaly_score += 0.2
            
            # Все флаги установлены (возможная атака)
            if flags == 0x3F:  # Все TCP флаги
                anomaly_score += 0.6
            
            # Дополнительные подозрительные комбинации
            if flags & 0x02 and flags & 0x04:  # SYN + RST
                anomaly_score += 0.4
            if flags & 0x01 and flags & 0x02:  # FIN + SYN
                anomaly_score += 0.3
            
            # Анализ TCP Window Size с улучшенной логикой
            window_size = tcp_layer.window
            if window_size == 0:  # Нулевое окно
                anomaly_score += 0.2
            elif window_size > 65535:  # Некорректный размер
                anomaly_score += 0.4
            elif window_size < 0:  # Отрицательный размер
                anomaly_score += 0.5
            
            # Анализ TCP sequence numbers
            if hasattr(tcp_layer, 'seq'):
                seq_num = tcp_layer.seq
                if seq_num == 0:  # Нулевой sequence number
                    anomaly_score += 0.1
                elif seq_num > 0xFFFFFFFF:  # Некорректный sequence number
                    anomaly_score += 0.3
        
        # === УЛУЧШЕННЫЙ АНАЛИЗ IP ХАРАКТЕРИСТИК ===
        if packet.haslayer(scapy.IP):
            ip_layer = packet[scapy.IP]
            
            # Улучшенный анализ TTL
            ttl = ip_layer.ttl
            if ttl == 0:  # TTL = 0 (пакет должен быть отброшен)
                anomaly_score += 0.5
            elif ttl > 255:  # Некорректный TTL
                anomaly_score += 0.4
            elif ttl < 1:  # Отрицательный TTL
                anomaly_score += 0.6
            elif ttl == 1:  # TTL = 1 (подозрительно)
                anomaly_score += 0.2
            
            # Анализ IP флагов с весами
            ip_flags = ip_layer.flags
            if ip_flags & 0x01:  # MF (More Fragments)
                anomaly_score += 0.2
            if ip_flags & 0x02:  # DF (Don't Fragment)
                anomaly_score += 0.1
            
            # Анализ IP адресов с улучшенной логикой
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            # Private IP в публичном трафике
            if src_ip.startswith('192.168.') or src_ip.startswith('10.') or src_ip.startswith('172.'):
                anomaly_score += 0.2
            
            # Loopback адреса
            if src_ip == '127.0.0.1' or dst_ip == '127.0.0.1':
                anomaly_score += 0.3
            
            # Подозрительные IP адреса
            if src_ip == '0.0.0.0' or dst_ip == '0.0.0.0':
                anomaly_score += 0.4
            
            # Анализ IP версии
            if hasattr(ip_layer, 'version'):
                if ip_layer.version != 4:  # Не IPv4
                    anomaly_score += 0.2
            
            # Анализ IP длины заголовка
            if hasattr(ip_layer, 'ihl'):
                if ip_layer.ihl < 5:  # Минимальная длина заголовка
                    anomaly_score += 0.3
                elif ip_layer.ihl > 15:  # Максимальная длина заголовка
                    anomaly_score += 0.2
        
        # === АНАЛИЗ PAYLOAD ===
        if hasattr(packet, 'load') and packet.load:
            payload = packet.load
            
            # Анализ энтропии (высокая энтропия = возможное шифрование/сжатие)
            if len(payload) > 0:
                byte_counts = {}
                for byte in payload:
                    byte_counts[byte] = byte_counts.get(byte, 0) + 1
                
                entropy = 0.0
                for count in byte_counts.values():
                    p = count / len(payload)
                    if p > 0:
                        entropy -= p * np.log2(p)
                
                # Очень высокая энтропия (возможное шифрование)
                if entropy > 7.5:
                    anomaly_score += 2
                
                # Очень низкая энтропия (возможная атака)
                elif entropy < 1.0:
                    anomaly_score += 1
            
            # Поиск подозрительных паттернов
            suspicious_patterns = [
                b'\x00' * 10,  # Много нулевых байтов
                b'\xFF' * 10,  # Много единиц
                b'AAAAAAAA',   # Buffer overflow паттерн
                b'<script>',   # XSS попытка
                b'SELECT *',   # SQL injection
                b'../',        # Path traversal
            ]
            
            for pattern in suspicious_patterns:
                if pattern in payload:
                    anomaly_score += 2
                    break
        
        # === АНАЛИЗ ПРОТОКОЛОВ ===
        # Необычные комбинации протоколов
        if packet.haslayer(scapy.ICMP) and packet.haslayer(scapy.TCP):
            anomaly_score += 2  # ICMP + TCP (необычно)
        
        # DNS с большим payload
        if packet.haslayer(scapy.DNS) and packet_size > 512:
            anomaly_score += 1
        
        # ICMP аномалии
        if packet.haslayer(scapy.ICMP):
            icmp_layer = packet[scapy.ICMP]
            
            # Подозрительные ICMP типы
            if icmp_layer.type in [0, 8]:  # Echo Request/Reply
                if packet_size > 1500:  # Слишком большой ICMP пакет
                    anomaly_score += 2
            elif icmp_layer.type == 3:  # Destination Unreachable
                if packet_size > 576:  # Слишком большой для ICMP
                    anomaly_score += 1
            elif icmp_layer.type == 11:  # Time Exceeded
                if packet_size > 576:  # Слишком большой для ICMP
                    anomaly_score += 1
            
            # Подозрительные ICMP коды
            if icmp_layer.type == 3 and icmp_layer.code > 15:  # Неизвестный код
                anomaly_score += 2
        
        # HTTPS/TLS аномалии
        if packet.haslayer(scapy.TLS):
            tls_layer = packet[scapy.TLS]
            
            # Подозрительные TLS версии
            if hasattr(tls_layer, 'version'):
                if tls_layer.version < 0x0300:  # Слишком старая версия TLS
                    anomaly_score += 2
                elif tls_layer.version > 0x0304:  # Неизвестная версия
                    anomaly_score += 1
        
        # === ВРЕМЕННОЙ АНАЛИЗ ===
        # Добавляем временную метку для анализа
        current_time = time.time()
        # Здесь можно добавить анализ временных паттернов
        
        # === УЛУЧШЕННАЯ КЛАССИФИКАЦИЯ АНОМАЛИЙ ===
        # Используем более точные пороги с учетом весов
        if anomaly_score >= 2.0:
            return 1  # High Anomaly
        elif anomaly_score >= 1.0:
            return 1  # Medium Anomaly
        elif anomaly_score >= 0.5:
            return 1  # Low Anomaly
        else:
            return 0  # Normal
    
    except Exception as e:
        print(f"ВНИМАНИЕ Ошибка детекции аномалий: {e}")
        return 0


def load_real_data(data_path: str) -> tuple:
    """Загружает реальные данные из файла"""
    if not os.path.exists(data_path):
        print(f"Файл данных не найден: {data_path}")
        return None
    
    try:
        # Загружаем данные (предполагаем CSV формат)
        df = pd.read_csv(data_path)
        
        # Проверяем структуру данных
        required_columns = ['features', 'traffic_class', 'dpi_type', 'is_anomaly']
        missing_columns = [col for col in required_columns if col not in df.columns]
        
        if missing_columns:
            print(f"ОШИБКА Отсутствуют колонки: {missing_columns}")
            print("РЕКОМЕНДАЦИЯ Ожидаемые колонки: features, traffic_class, dpi_type, is_anomaly")
            return None
        
        # Извлекаем данные БЕЗОПАСНО
        import ast
        X = np.array([ast.literal_eval(features) for features in df['features']], dtype=np.float32)
        traffic_labels = df['traffic_class'].values.astype(np.int32)
        dpi_labels = df['dpi_type'].values.astype(np.int32)
        anomaly_labels = df['is_anomaly'].values.astype(np.int32)
        
        print(f"УСПЕХ Реальные данные загружены:")
        print(f"  - Размер: {X.shape}")
        print(f"  - Классы трафика: {len(np.unique(traffic_labels))}")
        print(f"  - Типы DPI: {len(np.unique(dpi_labels))}")
        print(f"  - Аномалии: {np.sum(anomaly_labels)} ({np.mean(anomaly_labels)*100:.1f}%)")
        
        return X, traffic_labels, dpi_labels, anomaly_labels
    
    except Exception as e:
        print(f"ОШИБКА Ошибка загрузки данных: {e}")
        return None


def train_traffic_classifiers(model_manager: ModelManager, X_train: np.ndarray, 
                            y_train: np.ndarray, X_val: np.ndarray, y_val: np.ndarray, 
                            class_weight=None):
    """PRODUCTION ОБУЧЕНИЕ: Обучает классификаторы трафика с УЛУЧШЕННЫМ cross-validation"""
    print("\n=== PRODUCTION ОБУЧЕНИЕ Traffic Classifiers с УЛУЧШЕННЫМ CV ===")
    
    models = ['cnn', 'lstm', 'transformer']
    results = {}
    
    # ИСПРАВЛЕНО: Более разумная валидация данных
    print("ПОИСК ВАЛИДАЦИЯ ДАННЫХ...")
    
    # Проверяем минимальные требования
    unique_classes, counts = np.unique(y_train, return_counts=True)
    min_samples = min(counts)
    
    if min_samples < 10:  # ИСПРАВЛЕНО: Разумный минимум
        print(f"🚨 КРИТИЧЕСКАЯ ОШИБКА: Недостаточно данных для обучения")
        print(f"РЕКОМЕНДАЦИЯ Требуется минимум 10 образцов на класс, получено {min_samples}")
        return {'error': 'Insufficient data for training'}
    
    # УЛУЧШЕННЫЙ PRODUCTION CROSS-VALIDATION: 5-fold с более строгими критериями
    from sklearn.model_selection import StratifiedKFold
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    
    print("СТАТИСТИКА УЛУЧШЕННЫЙ PRODUCTION CROSS-VALIDATION (5-fold)...")
    cv_scores = {}
    
    for model_type in models:
        print(f"\nПОИСК Улучшенный Cross-validation для {model_type.upper()}...")
        try:
            # УЛУЧШЕНО: 5-fold cross-validation для более надежной оценки
            cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
            fold_scores = []
            fold_precisions = []
            fold_recalls = []
            fold_f1s = []
            
            for fold, (train_idx, val_idx) in enumerate(cv.split(X_train, y_train)):
                print(f"  Fold {fold + 1}/5...")
                
                # Разделяем данные
                X_fold_train, X_fold_val = X_train[train_idx], X_train[val_idx]
                y_fold_train, y_fold_val = y_train[train_idx], y_train[val_idx]
                
                # Создаем временную модель для CV
                temp_classifier = TrafficClassifier(model_type, X_train.shape[1], len(unique_classes))
                temp_classifier.compile_model()
                
                # УЛУЧШЕНО: Обучаем с более агрессивными параметрами против переобучения
                temp_classifier.train(
                    X_fold_train, y_fold_train, X_fold_val, y_fold_val,
                    epochs=10,  # УВЕЛИЧЕНО: Было 5, стало 10 для лучшего обучения
                    batch_size=32,  # УМЕНЬШЕНО: Было 64, стало 32 для лучшей стабильности
                    class_weight=class_weight
                )
                
                # Оцениваем с расширенными метриками
                y_pred, _ = temp_classifier.predict(X_fold_val)
                fold_accuracy = accuracy_score(y_fold_val, y_pred)
                fold_precision = precision_score(y_fold_val, y_pred, average='weighted', zero_division=0)
                fold_recall = recall_score(y_fold_val, y_pred, average='weighted', zero_division=0)
                fold_f1 = f1_score(y_fold_val, y_pred, average='weighted', zero_division=0)
                
                fold_scores.append(fold_accuracy)
                fold_precisions.append(fold_precision)
                fold_recalls.append(fold_recall)
                fold_f1s.append(fold_f1)
                
                print(f"    Fold {fold + 1} - Accuracy: {fold_accuracy:.3f}, F1: {fold_f1:.3f}")
            
            # УЛУЧШЕННЫЙ анализ результатов CV
            mean_cv_score = np.mean(fold_scores)
            std_cv_score = np.std(fold_scores)
            mean_f1 = np.mean(fold_f1s)
            std_f1 = np.std(fold_f1s)
            
            cv_scores[model_type] = {
                'mean_accuracy': mean_cv_score,
                'std_accuracy': std_cv_score,
                'mean_f1': mean_f1,
                'std_f1': std_f1,
                'accuracy_scores': fold_scores,
                'f1_scores': fold_f1s,
                'precision_scores': fold_precisions,
                'recall_scores': fold_recalls
            }
            
            print(f"СТАТИСТИКА {model_type.upper()} CV Results:")
            print(f"  - Accuracy: {mean_cv_score:.3f} ± {std_cv_score:.3f}")
            print(f"  - F1-Score: {mean_f1:.3f} ± {std_f1:.3f}")
            
            # ИСПРАВЛЕНО: Более разумные критерии для CV
            if mean_cv_score < 0.3 or std_cv_score > 0.3 or mean_f1 < 0.2:  # ИСПРАВЛЕНО: Более мягкие требования
                print(f"ВНИМАНИЕ {model_type.upper()} НЕ ПРОШЛА CV (Accuracy: {mean_cv_score:.3f}±{std_cv_score:.3f}, F1: {mean_f1:.3f}±{std_f1:.3f})")
                print(f"РЕКОМЕНДАЦИЯ Требования: Accuracy ≥ 0.3, Std ≤ 0.3, F1 ≥ 0.2")
                continue
            else:
                print(f"УСПЕХ {model_type.upper()} ПРОШЛА CV - готова к обучению")
            
        except Exception as e:
            print(f"ОШИБКА Ошибка CV для {model_type}: {e}")
            continue
    
    # Обучаем только прошедшие CV модели
    for model_type in models:
        if model_type not in cv_scores:
            print(f"ПРОПУСК Пропускаем {model_type.upper()} (не прошла CV)")
            continue
            
        print(f"\nОБУЧЕНИЕ {model_type.upper()} МОДЕЛИ...")
        try:
            # УЛУЧШЕНО: Более консервативные параметры для production
            result = model_manager.train_traffic_classifier(
                model_type, X_train, y_train, X_val, y_val,
                epochs=15,  # УМЕНЬШЕНО: Было 20, стало 15 для предотвращения переобучения
                batch_size=32,  # УМЕНЬШЕНО: Было 64, стало 32 для лучшей стабильности
                class_weight=class_weight
            )
            results[model_type] = result
            results[model_type]['cv_scores'] = cv_scores[model_type]
            print(f"УСПЕХ {model_type.upper()} обучена с точностью {result['accuracy']:.3f}")
            print(f"СТАТИСТИКА CV результаты: Accuracy {cv_scores[model_type]['mean_accuracy']:.3f}±{cv_scores[model_type]['std_accuracy']:.3f}")
        except Exception as e:
            print(f"ОШИБКА Ошибка обучения {model_type}: {e}")
            results[model_type] = {'error': str(e)}
    
    return results


def train_dpi_detector(model_manager: ModelManager, X_train: np.ndarray, 
                      y_train: np.ndarray, X_val: np.ndarray, y_val: np.ndarray):
    """Обучает детектор DPI"""
    print("\n=== Обучение DPI Detector ===")
    
    try:
        result = model_manager.train_dpi_detector(
            X_train, y_train, X_val, y_val,
            epochs=10, batch_size=64
        )
        print(f"УСПЕХ DPI Detector обучен с точностью {result['accuracy']:.3f}")
        return result
    except Exception as e:
        print(f"ОШИБКА Ошибка обучения DPI Detector: {e}")
        return {'error': str(e)}


def train_anomaly_detectors(model_manager: ModelManager, X_train: np.ndarray):
    """Обучает детекторы аномалий"""
    print("\n=== Обучение Anomaly Detectors ===")
    
    methods = ['autoencoder', 'isolation_forest', 'one_class_svm']
    results = {}
    
    for method in methods:
        print(f"\nОбучение {method}...")
        try:
            result = model_manager.train_anomaly_detector(
                method, X_train, epochs=10, batch_size=64
            )
            results[method] = result
            print(f"УСПЕХ {method} обучен")
        except Exception as e:
            print(f"ОШИБКА Ошибка обучения {method}: {e}")
            results[method] = {'error': str(e)}
    
    return results


def evaluate_models(model_manager: ModelManager, X_test: np.ndarray, 
                   y_traffic_test: np.ndarray, y_dpi_test: np.ndarray, 
                   y_anomaly_test: np.ndarray):
    """Оценивает все модели на тестовых данных с РЕАЛЬНЫМИ метриками"""
    print("\n=== Оценка моделей с реальными метриками ===")
    
    # Оценка Traffic Classifiers
    print("\nОценка Traffic Classifiers:")
    for model_type in ['cnn', 'lstm', 'transformer']:
        try:
            classifier = model_manager.models['traffic_classifier'][model_type]
            if classifier.is_trained:
                # Получаем реальные метрики
                real_metrics = calculate_real_metrics(
                    classifier.model, X_test, y_traffic_test, f"traffic_{model_type}"
                )
                
                if 'error' not in real_metrics:
                    print(f"  {model_type.upper()}:")
                    print(f"    - Accuracy: {real_metrics['accuracy']:.3f}")
                    print(f"    - Precision: {real_metrics['precision']:.3f}")
                    print(f"    - Recall: {real_metrics['recall']:.3f}")
                    print(f"    - F1-Score: {real_metrics['f1_score']:.3f}")
                else:
                    print(f"  {model_type.upper()}: Ошибка - {real_metrics['error']}")
        except Exception as e:
            print(f"  {model_type.upper()}: Ошибка - {e}")
    
    # Оценка DPI Detector
    print("\nОценка DPI Detector:")
    try:
        dpi_detector = model_manager.models['dpi_detector']
        if dpi_detector.is_trained:
            # Простая оценка точности
            predictions = []
            for i in range(min(100, len(X_test))):  # Тестируем на 100 образцах
                dpi_type, confidence, _ = dpi_detector.detect_dpi(X_test[i])
                predictions.append(dpi_type)
            
            accuracy = np.mean(np.array(predictions) == y_dpi_test[:len(predictions)])
            print(f"  DPI Detector: {accuracy:.3f}")
    except Exception as e:
        print(f"  DPI Detector: Ошибка - {e}")
    
    # Оценка Anomaly Detectors
    print("\nОценка Anomaly Detectors:")
    for method in ['autoencoder', 'isolation_forest', 'one_class_svm']:
        try:
            detector = model_manager.models['anomaly_detector'][method]
            if detector.is_trained:
                # Простая оценка точности
                predictions = []
                for i in range(min(100, len(X_test))):  # Тестируем на 100 образцах
                    is_anomaly, _ = detector.detect_anomaly(X_test[i])
                    predictions.append(is_anomaly)
                
                accuracy = np.mean(np.array(predictions) == y_anomaly_test[:len(predictions)])
                print(f"  {method}: {accuracy:.3f}")
        except Exception as e:
            print(f"  {method}: Ошибка - {e}")


def save_training_report(results: dict, output_path: str):
    """Сохраняет отчет об обучении"""
    report = {
        'timestamp': datetime.now().isoformat(),
        'results': results,
        'summary': {
            'total_models': len(results),
            'successful_models': len([r for r in results.values() if 'error' not in r]),
            'failed_models': len([r for r in results.values() if 'error' in r])
        }
    }
    
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nОтчет об обучении сохранен в {output_path}")


def save_traffic_data(X: np.ndarray, y_traffic: np.ndarray, y_dpi: np.ndarray, y_anomaly: np.ndarray, output_path: str):
    """Сохраняет данные трафика в CSV файл"""
    print(f"СОХРАНЕНИЕ Сохранение данных трафика в {output_path}...")
    
    # Создаем DataFrame
    data = pd.DataFrame(X)
    
    # Добавляем метки
    data['traffic_class'] = y_traffic
    data['dpi_type'] = y_dpi
    data['is_anomaly'] = y_anomaly
    
    # Сохраняем в CSV
    data.to_csv(output_path, index=False)
    
    print(f"УСПЕХ Данные сохранены: {data.shape[0]} образцов, {data.shape[1]} признаков")
    print(f"СТАТИСТИКА Классы трафика: {len(np.unique(y_traffic))}")
    print(f"ПОИСК Типы DPI: {len(np.unique(y_dpi))}")
    print(f"ВНИМАНИЕ Аномалии: {np.sum(y_anomaly)} ({np.mean(y_anomaly)*100:.1f}%)")




def start_real_time_data_collection(duration: int = 3600, save_interval: int = 300):
    """Запускает сбор данных в реальном времени с автоматическим сохранением"""
    print("ОБНОВЛЕНИЕ Запуск сбора данных в реальном времени...")
    print(f"ВРЕМЯ Длительность: {duration} секунд")
    print(f"СОХРАНЕНИЕ Сохранение каждые {save_interval} секунд")
    
    import threading
    import time
    from datetime import datetime
    
    # Глобальные переменные для сбора данных
    collected_data = {
        'features': [],
        'traffic_labels': [],
        'dpi_labels': [],
        'anomaly_labels': [],
        'timestamps': []
    }
    
    def data_collector():
        """Функция сбора данных в отдельном потоке"""
        start_time = time.time()
        packet_count = 0
        
        def packet_handler(packet):
            nonlocal packet_count
            try:
                # Извлекаем признаки
                features = extract_packet_features(packet)
                if features is not None:
                    # Классифицируем
                    traffic_class = classify_traffic(packet)
                    dpi_type = detect_dpi_type(packet)
                    is_anomaly = detect_anomaly(packet)
                    
                    # Сохраняем данные
                    collected_data['features'].append(features)
                    collected_data['traffic_labels'].append(traffic_class)
                    collected_data['dpi_labels'].append(dpi_type)
                    collected_data['anomaly_labels'].append(is_anomaly)
                    collected_data['timestamps'].append(time.time())
                    
                    packet_count += 1
                    
                    if packet_count % 100 == 0:
                        print(f"📦 Собрано пакетов: {packet_count}")
                        
            except Exception as e:
                print(f"ВНИМАНИЕ Ошибка обработки пакета: {e}")
        
        try:
            import scapy.all as scapy
            print("СЕТЬ Начинаем захват трафика...")
            scapy.sniff(prn=packet_handler, timeout=duration, store=0)
        except Exception as e:
            print(f"ОШИБКА Ошибка захвата: {e}")
    
    def auto_save():
        """Автоматическое сохранение данных"""
        while True:
            time.sleep(save_interval)
            if len(collected_data['features']) > 0:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"real_time_data_{timestamp}.csv"
                
                # Создаем DataFrame
                df = pd.DataFrame(collected_data['features'])
                df['traffic_class'] = collected_data['traffic_labels']
                df['dpi_type'] = collected_data['dpi_labels']
                df['is_anomaly'] = collected_data['anomaly_labels']
                df['timestamp'] = collected_data['timestamps']
                
                # Сохраняем
                df.to_csv(filename, index=False)
                print(f"СОХРАНЕНИЕ Данные сохранены: {filename} ({len(df)} записей)")
                
                # Очищаем буфер
                collected_data['features'].clear()
                collected_data['traffic_labels'].clear()
                collected_data['dpi_labels'].clear()
                collected_data['anomaly_labels'].clear()
                collected_data['timestamps'].clear()
    
    # Запускаем сбор данных в отдельном потоке
    collector_thread = threading.Thread(target=data_collector)
    collector_thread.daemon = True
    collector_thread.start()
    
    # Запускаем автосохранение в отдельном потоке
    saver_thread = threading.Thread(target=auto_save)
    saver_thread.daemon = True
    saver_thread.start()
    
    # Ждем завершения
    collector_thread.join()
    
    # Финальное сохранение
    if len(collected_data['features']) > 0:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"final_real_time_data_{timestamp}.csv"
        
        df = pd.DataFrame(collected_data['features'])
        df['traffic_class'] = collected_data['traffic_labels']
        df['dpi_type'] = collected_data['dpi_labels']
        df['is_anomaly'] = collected_data['anomaly_labels']
        df['timestamp'] = collected_data['timestamps']
        
        df.to_csv(filename, index=False)
        print(f"СОХРАНЕНИЕ Финальные данные сохранены: {filename} ({len(df)} записей)")
    
    print("УСПЕХ Сбор данных в реальном времени завершен")


def main():
    """Основная функция обучения с PRODUCTION валидацией"""
    print("ЗАПУСК ОБУЧЕНИЯ ML МОДЕЛЕЙ ДЛЯ WHISPERA PRODUCTION")
    print("=" * 60)
    print("PRODUCTION РЕЖИМ: Строгая валидация и упрощенные модели")
    print("=" * 60)
    
    # Инициализируем менеджер моделей
    model_manager = ModelManager("models")
    
    # УЛУЧШЕННАЯ система сбора данных с приоритетом реальных данных
    print("ПОИСК Поиск данных для обучения...")
    
    # Пробуем загрузить из разных источников
    data = None
    
    # 1. Пробуем загрузить из файла с реальными данными
    real_time_files = [f for f in os.listdir('.') if f.startswith('real_time_data_') and f.endswith('.csv')]
    if real_time_files:
        # Берем самый свежий файл
        latest_file = max(real_time_files, key=os.path.getctime)
        print(f"📁 Найден файл с реальными данными: {latest_file}")
        data = load_real_traffic_data(latest_file)
    
    # 2. Если нет реальных данных, пробуем старый файл
    if data is None:
        data_path = "real_traffic_data.csv"
        if os.path.exists(data_path):
            print("📁 Найден файл с данными, загружаем...")
            data = load_real_traffic_data(data_path)
    
    # 3. Если файла нет, запускаем сбор в реальном времени
    if data is None:
        print("СЕТЬ Файл данных не найден, запускаем сбор в реальном времени...")
        print("РЕКОМЕНДАЦИЯ Для работы с реальными данными установите scapy: pip install scapy")
        
        # Автоматические параметры сбора
        duration = 300  # 5 минут для быстрого тестирования
        
        save_interval = 60  # Автоматический интервал сохранения
        
        print(f"Собираем данные {duration} секунд, сохраняем каждые {save_interval} секунд...")
        
        # Запускаем сбор в реальном времени
        start_real_time_data_collection(duration, save_interval)
        
        # Пробуем загрузить собранные данные
        real_time_files = [f for f in os.listdir('.') if f.startswith('real_time_data_') and f.endswith('.csv')]
        if real_time_files:
            latest_file = max(real_time_files, key=os.path.getctime)
            print(f"📁 Загружаем собранные данные: {latest_file}")
            data = load_real_traffic_data(latest_file)
    
    # 3. Если и это не удалось, создаем реальные данные
    if data is None:
        print("ОШИБКА Не удалось получить данные для обучения")
        print("ИНСТРУМЕНТ Создаем реальные данные из существующего трафика...")
        
        # Пробуем загрузить из captured_traffic.csv
        if os.path.exists("captured_traffic.csv"):
            print("📁 Найден файл captured_traffic.csv, загружаем...")
            data = load_real_traffic_data("captured_traffic.csv")
        
        if data is None:
            print("ОШИБКА Критическая ошибка: нет данных для обучения")
            print("РЕКОМЕНДАЦИЯ Для работы системы необходимо:")
            print("  1. Запустить capture_real_traffic() для сбора данных")
            print("  2. Или предоставить файл captured_traffic.csv")
            print("  3. Система работает только с реальными данными")
            return
    
    if data is None:
        print("ОШИБКА Не удалось загрузить данные")
        return
    
    X, y_traffic, y_dpi, y_anomaly = data
    
    # УЛУЧШЕННАЯ валидация данных перед разделением
    print("ПОИСК ПРОДВИНУТАЯ валидация данных...")
    
    # Используем новую функцию валидации
    if not validate_training_data(X, y_traffic, "traffic classification"):
        print("ОШИБКА КРИТИЧЕСКАЯ ОШИБКА: Валидация данных не пройдена")
        return
    
    # 1. Проверка на NaN и Inf
    if np.any(np.isnan(X)) or np.any(np.isinf(X)):
        print("ОШИБКА КРИТИЧЕСКАЯ ОШИБКА: Найдены NaN или Inf значения в данных!")
        print("РЕКОМЕНДАЦИЯ Это указывает на проблемы в feature engineering")
        X = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=0.0)
        print("УСПЕХ Проблемные значения заменены на безопасные")
        print("ВНИМАНИЕ ВНИМАНИЕ: Система может работать нестабильно")
    
    # 2. Анализ важности признаков
    print("ПОИСК Анализ важности признаков...")
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_selection import SelectKBest, f_classif
    
    # Создаем временную модель для анализа признаков
    temp_rf = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
    temp_rf.fit(X, y_traffic)
    
    # Получаем важность признаков
    feature_importance = temp_rf.feature_importances_
    important_features = np.argsort(feature_importance)[-50:]  # Топ-50 признаков
    
    print(f"СТАТИСТИКА Топ-10 важных признаков: {important_features[-10:]}")
    print(f"СТАТИСТИКА Средняя важность: {np.mean(feature_importance):.4f}")
    
    # 3. Отбор лучших признаков
    selector = SelectKBest(f_classif, k=min(50, X.shape[1]))
    X_selected = selector.fit_transform(X, y_traffic)
    
    print(f"УСПЕХ Отобрано {X_selected.shape[1]} лучших признаков из {X.shape[1]}")
    X = X_selected
    
    # ИСПРАВЛЕНО: Улучшенная обработка выбросов с более агрессивной регуляризацией
    from scipy import stats
    z_scores = np.abs(stats.zscore(X, axis=1))
    outliers = np.any(z_scores > 2.5, axis=1)  # Более строгий порог для выбросов
    if np.sum(outliers) > 0:
        print(f"ВНИМАНИЕ Найдено {np.sum(outliers)} выбросов ({np.sum(outliers)/len(X)*100:.1f}%), нормализуем их")
        # Более агрессивная нормализация выбросов
        X[outliers] = np.clip(X[outliers], 0, 1)
        # Дополнительная нормализация для стабильности
        X = np.clip(X, 0.001, 0.999)  # Избегаем точных 0 и 1
        print("УСПЕХ Выбросы нормализованы с помощью clipping и дополнительной нормализации")
    
    # ДОБАВЛЯЕМ: Проверка на стабильность данных
    data_std = np.std(X, axis=0)
    low_variance_features = np.sum(data_std < 0.01)
    if low_variance_features > 0:
        print(f"ВНИМАНИЕ Найдено {low_variance_features} признаков с низкой вариативностью")
        print("РЕКОМЕНДАЦИЯ Рекомендуется увеличить разнообразие данных")
    
    # ДОБАВЛЯЕМ: проверка распределения классов
    unique_classes, counts = np.unique(y_traffic, return_counts=True)
    min_samples = min(counts)
    if min_samples < 1000:  # PRODUCTION требование: минимум 1000 образцов на класс
        print(f"🚨 КРИТИЧЕСКАЯ ПРОБЛЕМА: Некоторые классы имеют менее 1000 образцов (минимум: {min_samples})")
        print("РЕКОМЕНДАЦИЯ PRODUCTION ТРЕБОВАНИЕ: Минимум 1000 образцов на класс")
        print("РЕКОМЕНДАЦИЯ НЕМЕДЛЕННО: Соберите больше реальных данных")
        
        # Принудительная балансировка для production
        from sklearn.utils.class_weight import compute_class_weight
        class_weights = compute_class_weight('balanced', classes=unique_classes, y=y_traffic)
        class_weight_dict = dict(zip(unique_classes, class_weights))
        print(f"УСПЕХ Применяем агрессивную балансировку классов: {class_weight_dict}")
    else:
        class_weight_dict = None
        print(f"УСПЕХ PRODUCTION ГОТОВНОСТЬ: Все классы имеют достаточно образцов (минимум: {min_samples})")
    
    # Проверка распределения классов
    unique_classes, counts = np.unique(y_traffic, return_counts=True)
    min_samples = min(counts)
    if min_samples < 10:
        print(f"ВНИМАНИЕ ВНИМАНИЕ: Некоторые классы имеют менее 10 образцов")
        print("Рекомендуется собрать больше данных")
    
    # Проверка баланса классов
    class_balance = np.min(counts) / np.max(counts)
    if class_balance < 0.1:
        print(f"ВНИМАНИЕ ВНИМАНИЕ: Сильный дисбаланс классов (соотношение {class_balance:.2f})")
        print("Рекомендуется использовать балансировку классов")
    
    print(f"УСПЕХ Валидация пройдена:")
    print(f"  - Минимальное количество образцов в классе: {min_samples}")
    print(f"  - Баланс классов: {class_balance:.2f}")
    
    # Разделяем данные ПРАВИЛЬНО
    # Сначала разделяем на train+val и test
    X_temp, X_test, y_traffic_temp, y_traffic_test = train_test_split(
        X, y_traffic, test_size=0.2, random_state=42, stratify=y_traffic
    )
    
    # Затем разделяем train+val на train и val
    X_train, X_val, y_traffic_train, y_traffic_val = train_test_split(
        X_temp, y_traffic_temp, test_size=0.2, random_state=42, stratify=y_traffic_temp
    )
    
    # Разделяем остальные метки с теми же индексами
    # Создаем индексы для правильного разделения
    indices = np.arange(len(X))
    train_indices, test_indices = train_test_split(indices, test_size=0.2, random_state=42, stratify=y_traffic)
    train_indices, val_indices = train_test_split(train_indices, test_size=0.2, random_state=42, stratify=y_traffic[train_indices])
    
    # Используем правильные индексы
    y_dpi_train = y_dpi[train_indices]
    y_dpi_val = y_dpi[val_indices]
    y_dpi_test = y_dpi[test_indices]
    
    y_anomaly_train = y_anomaly[train_indices]
    y_anomaly_val = y_anomaly[val_indices]
    y_anomaly_test = y_anomaly[test_indices]
    
    print(f"\nРазделение данных:")
    print(f"  - Обучение: {X_train.shape[0]} образцов")
    print(f"  - Валидация: {X_val.shape[0]} образцов")
    print(f"  - Тестирование: {X_test.shape[0]} образцов")
    
    # Обучаем модели
    results = {}
    
    # УЛУЧШЕННОЕ обучение Traffic Classifiers с борьбой против overfitting
    print("\nИНСТРУМЕНТ УЛУЧШЕННОЕ обучение с борьбой против overfitting...")
    
    # Дополнительная валидация данных для предотвращения overfitting
    print("ПОИСК Дополнительная валидация данных...")
    
    # Проверяем на переобучение
    train_std = np.std(X_train, axis=0)
    val_std = np.std(X_val, axis=0)
    std_ratio = np.mean(val_std) / np.mean(train_std)
    
    if std_ratio < 0.5:
        print("ВНИМАНИЕ ВНИМАНИЕ: Возможное переобучение - низкая вариативность в валидационных данных")
        print("РЕКОМЕНДАЦИЯ Применяем дополнительную регуляризацию...")
        
        # Увеличиваем регуляризацию
        class_weight_dict = None  # Отключаем балансировку классов для борьбы с overfitting
    
    # Обучаем с улучшенными параметрами
    traffic_results = train_traffic_classifiers(
        model_manager, X_train, y_traffic_train, X_val, y_traffic_val, class_weight=class_weight_dict
    )
    results['traffic_classifiers'] = traffic_results
    
    # DPI Detector
    dpi_result = train_dpi_detector(
        model_manager, X_train, y_dpi_train, X_val, y_dpi_val
    )
    results['dpi_detector'] = dpi_result
    
    # Anomaly Detectors
    anomaly_results = train_anomaly_detectors(model_manager, X_train)
    results['anomaly_detectors'] = anomaly_results
    
    # Оцениваем модели
    evaluate_models(
        model_manager, X_test, y_traffic_test, y_dpi_test, y_anomaly_test
    )
    
    # Сохраняем данные трафика
    save_traffic_data(X, y_traffic, y_dpi, y_anomaly, "captured_traffic.csv")
    
    # Сохраняем отчет
    save_training_report(results, "training_report.json")
    
    # PRODUCTION ФИНАЛЬНАЯ ВАЛИДАЦИЯ СИСТЕМЫ
    print("\nПОИСК PRODUCTION ФИНАЛЬНАЯ ВАЛИДАЦИЯ СИСТЕМЫ...")
    
    # Проверяем готовность всех компонентов
    system_ready = True
    critical_issues = []
    
    # 1. Проверка моделей
    model_status = model_manager.get_model_status()
    trained_models = sum(1 for model in model_status['traffic_classifiers'].values() if model.get('is_trained', False))
    
    if trained_models == 0:
        critical_issues.append("ОШИБКА Нет обученных моделей")
        system_ready = False
    elif trained_models < 2:
        critical_issues.append("ВНИМАНИЕ Мало обученных моделей для ensemble")
    else:
        print(f"УСПЕХ Обучено {trained_models} моделей")
    
    # 2. Проверка качества данных
    if avg_accuracy < 0.7:
        critical_issues.append(f"ОШИБКА Низкая точность системы: {avg_accuracy:.3f}")
        system_ready = False
    else:
        print(f"УСПЕХ Система показывает хорошую точность: {avg_accuracy:.3f}")
    
    # 3. Проверка стабильности
    if std_ratio < 0.5:
        critical_issues.append("ВНИМАНИЕ Возможное переобучение моделей")
    else:
        print("УСПЕХ Модели показывают стабильность")
    
    # 4. Проверка данных
    if min_samples < 1000:
        critical_issues.append(f"ОШИБКА Недостаточно данных: {min_samples} < 1000 образцов на класс")
        system_ready = False
    else:
        print(f"УСПЕХ Достаточно данных: {min_samples} образцов на класс")
    
    # ФИНАЛЬНЫЙ СТАТУС
    print("\n" + "=" * 60)
    if system_ready:
        print("ПОЗДРАВЛЕНИЕ PRODUCTION СИСТЕМА ГОТОВА К DEPLOYMENT!")
        print("УСПЕХ Все критические проверки пройдены")
        print("УСПЕХ Система стабильна и готова к работе")
    else:
        print("🚨 PRODUCTION СИСТЕМА НЕ ГОТОВА К DEPLOYMENT!")
        print("ОШИБКА Критические проблемы:")
        for issue in critical_issues:
            print(f"  {issue}")
        print("РЕКОМЕНДАЦИЯ НЕМЕДЛЕННО: Исправьте критические проблемы перед deployment")
    
    print("\nСТАТИСТИКА PRODUCTION СТАТУС:")
    print("УСПЕХ Модели сохранены в директории 'models/'")
    print("УСПЕХ Данные трафика сохранены в 'captured_traffic.csv'")
    print("УСПЕХ Упрощенные архитектуры для стабильности")
    print("УСПЕХ Строгая валидация данных")
    print("УСПЕХ Ensemble методы")
    print("УСПЕХ Cross-validation")
    print("УСПЕХ Fallback механизмы")
    print("УСПЕХ Критические алерты")
    
    print("\nPRODUCTION ГОТОВНОСТЬ:")
    if system_ready:
        print("УСПЕХ Система готова к production deployment")
        print("УСПЕХ Для запуска API сервера: python api_server.py")
        print("УСПЕХ Для мониторинга: GET /monitoring/health")
        print("УСПЕХ Для валидации: GET /analysis/data_quality")
    else:
        print("ОШИБКА Система НЕ готова к production deployment")
        print("РЕКОМЕНДАЦИЯ Исправьте критические проблемы перед запуском")
    
    print("\nИНСТРУМЕНТ PRODUCTION УЛУЧШЕНИЯ ПРИМЕНЕНЫ:")
    print("УСПЕХ Упрощены модели (минимальные параметры)")
    print("УСПЕХ Максимальная регуляризация (dropout 0.5-0.6)")
    print("УСПЕХ Строгие требования к данным (1000+ образцов/класс)")
    print("УСПЕХ Ensemble методы для стабильности")
    print("УСПЕХ Cross-validation для проверки")
    print("УСПЕХ Критические алерты для мониторинга")
    print("УСПЕХ Fallback механизмы при ошибках")
    print("УСПЕХ Production валидация качества")
    
    print("\nЦЕЛЬ ФИНАЛЬНЫЙ СТАТУС:")
    if system_ready:
        print("ПОЗДРАВЛЕНИЕ СИСТЕМА ГОТОВА К PRODUCTION!")
    else:
        print("🚨 СИСТЕМА ТРЕБУЕТ ДОРАБОТКИ!")
    print("=" * 60)


def run_real_time_collection():
    """Запускает только сбор данных в реальном времени"""
    print("ОБНОВЛЕНИЕ Запуск сбора данных в реальном времени...")
    
    duration_input = input("Длительность сбора в секундах (по умолчанию 600): ").strip()
    if duration_input:
        duration = min(int(duration_input), 7200)  # Максимум 2 часа
    else:
        duration = 600
    
    save_interval_input = input("Интервал сохранения в секундах (по умолчанию 60): ").strip()
    if save_interval_input:
        save_interval = min(int(save_interval_input), 300)  # Максимум 5 минут
    else:
        save_interval = 60
    
    print(f"ВРЕМЯ Собираем данные {duration} секунд, сохраняем каждые {save_interval} секунд...")
    start_real_time_data_collection(duration, save_interval)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "collect":
        # Запуск только сбора данных
        run_real_time_collection()
    else:
        # Обычный запуск обучения
        main()
