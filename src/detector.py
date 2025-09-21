import re
import logging
import pickle
import json
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import defaultdict, deque
import hashlib
import uuid
import os

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import yaml

logger = logging.getLogger(__name__)

@dataclass
class DetectionResult:
    event_id: str
    threat_types: List[str]
    severity: str
    confidence: float
    matched_rules: List[str]
    ml_score: Optional[float] = None
    anomaly_score: Optional[float] = None
    reason: str = ""
    sanitized_excerpt: str = ""

class RuleEngine:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rules = self.load_rules()
        self.rule_stats = defaultdict(int)

    def load_rules(self) -> Dict[str, List[Dict]]:
        """Load detection rules from configuration"""
        rules = {'sqli': [], 'xss': [], 'command_injection': [], 'path_traversal': [], 'ssrf': [], 'log4shell': []}

        # Load from config
        config_rules = self.config.get('rules', {})
        for category, rule_list in config_rules.items():
            if category in rules:
                for rule in rule_list:
                    rules[category].append({
                        'pattern': rule['pattern'],
                        'severity': rule.get('severity', 'medium'),
                        'enabled': rule.get('enabled', True)
                    })

        # Additional sophisticated patterns
        rules['sqli'].extend([
            {
                'pattern': r'(?i)(select\s+\*\s+from\s+information_schema|union\s+all\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1)',
                'severity': 'high',
                'enabled': True
            },
            {
                'pattern': r'(?i)(waitfor\s+delay\s+\'|pg_sleep\s*\(|benchmark\s*\(|dbms_pipe\.receive_message)',
                'severity': 'critical',
                'enabled': True
            },
            {
                'pattern': r'(?i)(/\*.*\*/|--|#|;)\s*(union|select|insert|delete|update|drop|alter)',
                'severity': 'high',
                'enabled': True
            }
        ])

        rules['xss'].extend([
            {
                'pattern': r'(?i)(<\s*script[^>]*>.*<\s*\/\s*script\s*>|javascript\s*:|on\w+\s*=\s*["\'][^"\']*["\'])',
                'severity': 'high',
                'enabled': True
            },
            {
                'pattern': r'(?i)(document\.(cookie|domain)|window\.(location|name)|alert\s*\(|prompt\s*\(|confirm\s*\()',
                'severity': 'medium',
                'enabled': True
            },
            {
                'pattern': r'(?i)(expression\s*\(|eval\s*\(|fromcharcode|String\.fromCharCode)',
                'severity': 'high',
                'enabled': True
            }
        ])

        rules['command_injection'].extend([
            {
                'pattern': r'(?i)(\|\||&&|;\s*\w+|`\s*\w+|\$\(\s*\w+|nc\s+-l|netcat\s+-e)',
                'severity': 'critical',
                'enabled': True
            },
            {
                'pattern': r'(?i)(/bin/(sh|bash|dash|zsh)|cmd\.exe|powershell\.exe|wscript\.exe)',
                'severity': 'critical',
                'enabled': True
            }
        ])

        rules['path_traversal'].extend([
            {
                'pattern': r'(?i)(\.\.\/|\.\.\\\|/etc/passwd|/etc/shadow|c:\\\\windows\\\\system32)',
                'severity': 'high',
                'enabled': True
            },
            {
                'pattern': r'(?i)(file:\/\/|ftp:\/\/|gopher:\/\/|data:\/\/|phar:\/\/)',
                'severity': 'medium',
                'enabled': True
            }
        ])

        rules['ssrf'].extend([
            {
                'pattern': r'(?i)(url\s*=|http:\/\/|https:\/\/|ftp:\/\/).*localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])',
                'severity': 'high',
                'enabled': True
            }
        ])

        rules['log4shell'].extend([
            {
                'pattern': r'(?i)(\$\{jndi:|\$\{ldap:|\$\{rmi:|\$\{dns:)',
                'severity': 'critical',
                'enabled': True
            }
        ])

        return rules

    def check_rules(self, event: Dict[str, Any], text: str) -> List[Dict[str, Any]]:
        """Check event against all enabled rules"""
        matches = []

        for category, rules in self.rules.items():
            for rule in rules:
                if not rule.get('enabled', True):
                    continue

                try:
                    pattern = re.compile(rule['pattern'])
                    if pattern.search(text):
                        matches.append({
                            'category': category,
                            'severity': rule['severity'],
                            'pattern': rule['pattern'],
                            'rule_id': f"{category}_{len(matches)}"
                        })
                        self.rule_stats[category] += 1
                except re.error as e:
                    logger.warning(f"Invalid regex pattern in rule {rule}: {e}")

        return matches

class MachineLearningDetector:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 3), stop_words='english')
        self.scaler = StandardScaler()
        self.model = LogisticRegression(random_state=42, max_iter=1000)
        self.is_trained = False
        self.model_path = config.get('detector', {}).get('ml_model_path', 'models/')

    def extract_features(self, text: str) -> np.ndarray:
        """Extract TF-IDF features from text"""
        # Preprocess text
        text = text.lower()
        text = re.sub(r'[^\w\s]', ' ', text)
        text = re.sub(r'\s+', ' ', text).strip()

        # Extract features
        features = []

        # Length features
        features.append(len(text))
        features.append(len(text.split()))
        features.append(text.count('/'))
        features.append(text.count('?'))
        features.append(text.count('='))
        features.append(text.count('&'))
        features.append(text.count(';'))
        features.append(text.count("'"))
        features.append(text.count('"'))
        features.append(text.count(' '))

        # Special character ratio
        if len(text) > 0:
            special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
            features.append(special_chars / len(text))
        else:
            features.append(0)

        # Uppercase ratio
        if len(text) > 0:
            uppercase_ratio = sum(1 for c in text if c.isupper()) / len(text)
            features.append(uppercase_ratio)
        else:
            features.append(0)

        # Keyword features
        sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'union', 'or', 'and']
        xss_keywords = ['script', 'javascript', 'onerror', 'onload', 'alert', 'document']
        cmd_keywords = ['cmd', 'shell', 'exec', 'system', 'eval', 'nc', 'netcat']

        for keyword in sql_keywords:
            features.append(text.count(keyword))
        for keyword in xss_keywords:
            features.append(text.count(keyword))
        for keyword in cmd_keywords:
            features.append(text.count(keyword))

        return np.array(features)

    def train(self, texts: List[str], labels: List[int]) -> Dict[str, Any]:
        """Train the ML model"""
        try:
            # Extract features
            features = np.array([self.extract_features(text) for text in texts])

            # Scale features
            features_scaled = self.scaler.fit_transform(features)

            # Train model
            self.model.fit(features_scaled, labels)
            self.is_trained = True

            # Save model
            os.makedirs(self.model_path, exist_ok=True)
            with open(os.path.join(self.model_path, 'ml_model.pkl'), 'wb') as f:
                pickle.dump({
                    'vectorizer': self.vectorizer,
                    'scaler': self.scaler,
                    'model': self.model
                }, f)

            # Calculate training metrics
            predictions = self.model.predict(features_scaled)
            report = classification_report(labels, predictions, output_dict=True)

            return {
                'status': 'success',
                'samples': len(texts),
                'accuracy': report['accuracy'],
                'precision': report['weighted avg']['precision'],
                'recall': report['weighted avg']['recall'],
                'f1': report['weighted avg']['f1-score']
            }

        except Exception as e:
            logger.error(f"Training failed: {e}")
            return {'status': 'error', 'message': str(e)}

    def load_model(self) -> bool:
        """Load trained model from disk"""
        try:
            model_file = os.path.join(self.model_path, 'ml_model.pkl')
            if os.path.exists(model_file):
                with open(model_file, 'rb') as f:
                    data = pickle.load(f)
                    self.scaler = data['scaler']
                    self.model = data['model']
                    self.is_trained = True
                    return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")

        return False

    def predict(self, text: str) -> Tuple[float, bool]:
        """Make prediction for a text sample"""
        if not self.is_trained and not self.load_model():
            return 0.0, False

        try:
            features = self.extract_features(text)
            features_scaled = self.scaler.transform(features.reshape(1, -1))

            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba(features_scaled)[0]
                malicious_prob = proba[1] if len(proba) > 1 else proba[0]
            else:
                prediction = self.model.predict(features_scaled)[0]
                malicious_prob = 1.0 if prediction == 1 else 0.0

            return malicious_prob, True
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return 0.0, False

class AnomalyDetector:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.window_size = config.get('correlator', {}).get('window_seconds', 60)
        self.baseline_window = config.get('detector', {}).get('anomaly_window', 3600)
        self.baseline_data = defaultdict(lambda: deque(maxlen=1000))
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.is_baseline_trained = False

    def extract_session_features(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract features from session events"""
        if not events:
            return {}

        features = {
            'event_count': len(events),
            'unique_ips': len(set(e.get('source_ip') for e in events if e.get('source_ip'))),
            'unique_paths': len(set(e.get('http_path') for e in events if e.get('http_path'))),
            'unique_methods': len(set(e.get('http_method') for e in events if e.get('http_method'))),
            'error_count': sum(1 for e in events if str(e.get('http_status', '')).startswith('4') or str(e.get('http_status', '')).startswith('5')),
            'unique_agents': len(set(e.get('http_user_agent') for e in events if e.get('http_user_agent'))),
            'avg_request_length': np.mean([len(str(e.get('message', ''))) for e in events]) if events else 0,
            'time_span': (max(e.get('timestamp', '') for e in events) - min(e.get('timestamp', '') for e in events)).total_seconds() if len(events) > 1 else 0
        }

        # Request frequency
        if features['time_span'] > 0:
            features['requests_per_second'] = features['event_count'] / features['time_span']
        else:
            features['requests_per_second'] = 0

        return features

    def update_baseline(self, session_key: str, features: Dict[str, Any]):
        """Update baseline data with new session features"""
        if session_key not in self.baseline_data:
            self.baseline_data[session_key] = deque(maxlen=1000)

        self.baseline_data[session_key].append(features)

    def detect_anomaly(self, session_key: str, features: Dict[str, Any]) -> Tuple[float, bool]:
        """Detect anomalies in session features"""
        if session_key not in self.baseline_data or len(self.baseline_data[session_key]) < 10:
            return 0.0, False

        try:
            # Prepare baseline data
            baseline_features = []
            for bf in self.baseline_data[session_key]:
                baseline_features.append([
                    bf.get('event_count', 0),
                    bf.get('unique_ips', 0),
                    bf.get('unique_paths', 0),
                    bf.get('error_count', 0),
                    bf.get('requests_per_second', 0),
                    bf.get('avg_request_length', 0)
                ])

            current_features = [
                features.get('event_count', 0),
                features.get('unique_ips', 0),
                features.get('unique_paths', 0),
                features.get('error_count', 0),
                features.get('requests_per_second', 0),
                features.get('avg_request_length', 0)
            ]

            # Fit isolation forest on baseline
            self.isolation_forest.fit(baseline_features)
            self.is_baseline_trained = True

            # Predict anomaly
            anomaly_score = self.isolation_forest.decision_function([current_features])[0]
            is_anomaly = self.isolation_forest.predict([current_features])[0] == -1

            return abs(anomaly_score), is_anomaly

        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            return 0.0, False

class ThreatDetector:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rule_engine = RuleEngine(config)
        self.ml_detector = MachineLearningDetector(config)
        self.anomaly_detector = AnomalyDetector(config)
        self.session_tracking = defaultdict(list)

    def get_detection_text(self, event: Dict[str, Any]) -> str:
        """Extract text for detection from event"""
        text_parts = []

        # Add message
        if event.get('message'):
            text_parts.append(event['message'])

        # Add HTTP path and query
        if event.get('http_path'):
            text_parts.append(event['http_path'])
        if event.get('query_params'):
            for key, value in event['query_params'].items():
                text_parts.append(f"{key}={value}")

        # Add database query
        if event.get('decoded_query'):
            text_parts.append(event['decoded_query'])
        elif event.get('query'):
            text_parts.append(event['query'])

        # Add cloud action
        if event.get('cloud_action'):
            text_parts.append(event['cloud_action'])

        return ' '.join(text_parts)

    def determine_severity(self, rule_matches: List[Dict], ml_score: float, anomaly_score: float) -> str:
        """Determine overall severity based on all detections"""
        severity_scores = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        max_severity_score = 0

        # Rule-based severity
        for match in rule_matches:
            score = severity_scores.get(match['severity'], 1)
            max_severity_score = max(max_severity_score, score)

        # Boost severity based on ML confidence
        if ml_score > 0.9:
            max_severity_score = min(max_severity_score + 1, 4)
        elif ml_score > 0.7:
            max_severity_score = min(max_severity_score + 0.5, 4)

        # Boost severity based on anomaly
        if anomaly_score > 0.8:
            max_severity_score = min(max_severity_score + 1, 4)

        # Convert back to severity string
        for severity, score in severity_scores.items():
            if max_severity_score >= score:
                return severity

        return 'low'

    def create_sanitized_excerpt(self, text: str, max_length: int = 200) -> str:
        """Create sanitized excerpt for reporting"""
        if len(text) <= max_length:
            return text

        return text[:max_length] + "..."

    def detect_threats(self, event: Dict[str, Any]) -> DetectionResult:
        """Perform comprehensive threat detection on an event"""
        event_id = event.get('event_id', str(uuid.uuid4()))
        detection_text = self.get_detection_text(event)

        # Rule-based detection
        rule_matches = self.rule_engine.check_rules(event, detection_text)

        # Machine learning detection
        ml_score, ml_success = self.ml_detector.predict(detection_text) if self.config.get('detector', {}).get('enable_ml', True) else (0.0, False)

        # Anomaly detection
        anomaly_score = 0.0
        session_key = event.get('source_ip') or event.get('tenant')

        if session_key:
            # Add to session tracking
            self.session_tracking[session_key].append(event)

            # Remove old events beyond window
            window_cutoff = datetime.now() - timedelta(seconds=self.window_size)
            self.session_tracking[session_key] = [
                e for e in self.session_tracking[session_key]
                if datetime.fromisoformat(e.get('timestamp', '')) > window_cutoff
            ]

            # Extract session features and update baseline
            session_features = self.anomaly_detector.extract_session_features(self.session_tracking[session_key])
            self.anomaly_detector.update_baseline(session_key, session_features)

            # Detect anomalies
            anomaly_score, is_anomaly = self.anomaly_detector.detect_anomaly(session_key, session_features)

        # Determine threat types
        threat_types = []
        for match in rule_matches:
            if match['category'] not in threat_types:
                threat_types.append(match['category'])

        if ml_score > 0.8:
            threat_types.append('ml_anomaly')

        if anomaly_score > 0.7:
            threat_types.append('behavioral_anomaly')

        # Calculate overall confidence
        confidence = 0.0
        if rule_matches:
            confidence = max(confidence, 0.8)
        if ml_score > 0.7:
            confidence = max(confidence, ml_score)
        if anomaly_score > 0.7:
            confidence = max(confidence, anomaly_score * 0.8)

        # Determine severity
        severity = self.determine_severity(rule_matches, ml_score, anomaly_score)

        # Build reason string
        reason_parts = []
        if rule_matches:
            rule_names = [f"{m['category']}_{i}" for i, m in enumerate(rule_matches)]
            reason_parts.append(f"matched rules: {', '.join(rule_names)}")
        if ml_score > 0.7:
            reason_parts.append(f"ml_score={ml_score:.2f}")
        if anomaly_score > 0.7:
            reason_parts.append(f"anomaly_score={anomaly_score:.2f}")

        reason = "; ".join(reason_parts) if reason_parts else "no significant threats detected"

        return DetectionResult(
            event_id=event_id,
            threat_types=threat_types,
            severity=severity,
            confidence=confidence,
            matched_rules=[f"{m['category']}_{i}" for i, m in enumerate(rule_matches)],
            ml_score=ml_score if ml_success else None,
            anomaly_score=anomaly_score if anomaly_score > 0 else None,
            reason=reason,
            sanitized_excerpt=self.create_sanitized_excerpt(detection_text)
        )

    def train_ml_model(self, texts: List[str], labels: List[int]) -> Dict[str, Any]:
        """Train ML model with provided data"""
        return self.ml_detector.train(texts, labels)

    def get_rule_stats(self) -> Dict[str, int]:
        """Get rule match statistics"""
        return dict(self.rule_engine.rule_stats)