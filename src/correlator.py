import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import defaultdict, deque
import hashlib
import uuid
import json

from .detector import DetectionResult

logger = logging.getLogger(__name__)

@dataclass
class CorrelatedEvent:
    event_id: str
    correlation_id: str
    timestamp: datetime
    severity: str
    threat_types: List[str]
    source_ip: Optional[str]
    tenant: Optional[str]
    session_id: Optional[str]
    user: Optional[str]
    matched_rules: List[str]
    ml_score: Optional[float]
    anomaly_score: Optional[float]
    window_hits: int
    reason: str

class EventCorrelator:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.window_seconds = config.get('correlator', {}).get('window_seconds', 60)
        self.dedup_ttl = config.get('correlator', {}).get('dedup_ttl', 600)  # 10 minutes
        self.max_events_per_window = config.get('correlator', {}).get('max_events_per_window', 100)

        # Data structures for correlation
        self.event_windows = defaultdict(lambda: deque(maxlen=self.max_events_per_window))
        self.dedup_cache = {}  # fingerprint -> timestamp
        self.suppression_list = {}  # target -> expiry_time
        self.correlation_stats = defaultdict(int)

    def generate_fingerprint(self, event: Dict[str, Any]) -> str:
        """Generate fingerprint for deduplication"""
        # Extract key fields for fingerprinting
        key_fields = [
            event.get('source_ip'),
            event.get('http_method'),
            event.get('http_path'),
            event.get('tenant'),
            event.get('severity')
        ]

        # Add threat types if present
        if 'threat_types' in event:
            key_fields.extend(sorted(event['threat_types']))

        # Create fingerprint string
        fingerprint_str = '|'.join(str(field) for field in key_fields if field)

        # Hash the fingerprint
        return hashlib.md5(fingerprint_str.encode()).hexdigest()

    def is_duplicate(self, event: Dict[str, Any]) -> bool:
        """Check if event is a duplicate"""
        fingerprint = self.generate_fingerprint(event)
        current_time = datetime.now()

        if fingerprint in self.dedup_cache:
            last_seen = self.dedup_cache[fingerprint]
            if (current_time - last_seen).total_seconds() < self.dedup_ttl:
                return True

        # Update cache
        self.dedup_cache[fingerprint] = current_time
        return False

    def is_suppressed(self, event: Dict[str, Any]) -> bool:
        """Check if event should be suppressed"""
        current_time = datetime.now()

        # Check IP suppression
        source_ip = event.get('source_ip')
        if source_ip and source_ip in self.suppression_list:
            if current_time < self.suppression_list[source_ip]:
                return True
            else:
                # Remove expired suppression
                del self.suppression_list[source_ip]

        # Check tenant suppression
        tenant = event.get('tenant')
        tenant_key = f"tenant:{tenant}"
        if tenant_key in self.suppression_list:
            if current_time < self.suppression_list[tenant_key]:
                return True
            else:
                del self.suppression_list[tenant_key]

        return False

    def add_suppression(self, target: str, ttl_seconds: int):
        """Add suppression rule"""
        expiry_time = datetime.now() + timedelta(seconds=ttl_seconds)
        self.suppression_list[target] = expiry_time

    def get_correlation_key(self, event: Dict[str, Any]) -> List[str]:
        """Get correlation keys for event"""
        keys = []

        # IP-based correlation
        if event.get('source_ip'):
            keys.append(f"ip:{event['source_ip']}")

        # Tenant-based correlation
        if event.get('tenant'):
            keys.append(f"tenant:{event['tenant']}")

        # Session-based correlation
        if event.get('session_id'):
            keys.append(f"session:{event['session_id']}")

        # User-based correlation
        if event.get('user'):
            keys.append(f"user:{event['user']}")

        # User agent correlation (for browser attacks)
        if event.get('http_user_agent'):
            ua_fingerprint = hashlib.md5(event['http_user_agent'].encode()).hexdigest()[:8]
            keys.append(f"ua:{ua_fingerprint}")

        return keys

    def analyze_window(self, key: str, detection_result: DetectionResult) -> Dict[str, Any]:
        """Analyze events in correlation window"""
        current_time = datetime.now()
        window_start = current_time - timedelta(seconds=self.window_seconds)

        # Get events in window
        window_events = [
            event for event in self.event_windows[key]
            if event.timestamp >= window_start
        ]

        if not window_events:
            return {
                'window_hits': 1,
                'unique_threat_types': set(detection_result.threat_types),
                'severity_counts': {detection_result.severity: 1},
                'max_severity': detection_result.severity,
                'should_correlate': False
            }

        # Analyze window patterns
        threat_types = set()
        severity_counts = defaultdict(int)
        max_severity_score = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(detection_result.severity, 1)

        # Add current event threats
        threat_types.update(detection_result.threat_types)
        severity_counts[detection_result.severity] += 1

        # Analyze existing events
        for event in window_events:
            threat_types.update(event.threat_types)
            severity_counts[event.severity] += 1
            current_score = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(event.severity, 1)
            max_severity_score = max(max_severity_score, current_score)

        # Determine if correlation is needed
        should_correlate = False
        correlation_reasons = []

        # Multiple threat types
        if len(threat_types) >= 2:
            should_correlate = True
            correlation_reasons.append(f"multiple threat types: {list(threat_types)}")

        # High frequency of events
        if len(window_events) >= 5:
            should_correlate = True
            correlation_reasons.append(f"high frequency: {len(window_events)} events in {self.window_seconds}s")

        # Multiple high severity events
        high_severity_count = severity_counts.get('critical', 0) + severity_counts.get('high', 0)
        if high_severity_count >= 2:
            should_correlate = True
            correlation_reasons.append(f"multiple high severity events: {high_severity_count}")

        # Escalation pattern (low -> high severity)
        if len(window_events) >= 3:
            severities = [event.severity for event in window_events]
            if 'low' in severities and 'high' in severities or 'critical' in severities:
                should_correlate = True
                correlation_reasons.append("severity escalation pattern detected")

        return {
            'window_hits': len(window_events) + 1,
            'unique_threat_types': threat_types,
            'severity_counts': dict(severity_counts),
            'max_severity': max_severity_score,
            'should_correlate': should_correlate,
            'correlation_reasons': correlation_reasons
        }

    def correlate_event(self, event: Dict[str, Any], detection_result: DetectionResult) -> CorrelatedEvent:
        """Correlate event with existing events"""
        correlation_keys = self.get_correlation_key(event)

        # Analyze each correlation key
        best_window_analysis = None
        best_key = None

        for key in correlation_keys:
            window_analysis = self.analyze_window(key, detection_result)

            if (best_window_analysis is None or
                window_analysis['window_hits'] > best_window_analysis['window_hits'] or
                (window_analysis['window_hits'] == best_window_analysis['window_hits'] and
                 window_analysis['should_correlate'])):
                best_window_analysis = window_analysis
                best_key = key

        # Generate correlation ID
        if best_window_analysis['should_correlate'] and best_key:
            correlation_id = f"corr_{hashlib.md5(best_key.encode()).hexdigest()[:12]}"
        else:
            correlation_id = f"single_{event.get('event_id', str(uuid.uuid4()))[:8]}"

        # Determine final severity based on correlation
        final_severity = detection_result.severity
        if best_window_analysis:
            severity_score_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
            max_score = best_window_analysis['max_severity']

            # Boost severity based on correlation
            if best_window_analysis['should_correlate']:
                max_score = min(max_score + 1, 4)

            # Convert back to severity string
            for severity, score in severity_score_map.items():
                if max_score >= score:
                    final_severity = severity
                    break

        # Add current event to windows
        current_time = datetime.now()
        if best_key:
            correlated_event = CorrelatedEvent(
                event_id=event.get('event_id', str(uuid.uuid4())),
                correlation_id=correlation_id,
                timestamp=current_time,
                severity=final_severity,
                threat_types=list(best_window_analysis['unique_threat_types']) if best_window_analysis else detection_result.threat_types,
                source_ip=event.get('source_ip'),
                tenant=event.get('tenant'),
                session_id=event.get('session_id'),
                user=event.get('user'),
                matched_rules=detection_result.matched_rules,
                ml_score=detection_result.ml_score,
                anomaly_score=detection_result.anomaly_score,
                window_hits=best_window_analysis['window_hits'] if best_window_analysis else 1,
                reason=detection_result.reason
            )

            self.event_windows[best_key].append(correlated_event)

        else:
            correlated_event = CorrelatedEvent(
                event_id=event.get('event_id', str(uuid.uuid4())),
                correlation_id=correlation_id,
                timestamp=current_time,
                severity=final_severity,
                threat_types=detection_result.threat_types,
                source_ip=event.get('source_ip'),
                tenant=event.get('tenant'),
                session_id=event.get('session_id'),
                user=event.get('user'),
                matched_rules=detection_result.matched_rules,
                ml_score=detection_result.ml_score,
                anomaly_score=detection_result.anomaly_score,
                window_hits=1,
                reason=detection_result.reason
            )

        # Update statistics
        self.correlation_stats['total_events'] += 1
        if best_window_analysis and best_window_analysis['should_correlate']:
            self.correlation_stats['correlated_events'] += 1

        return correlated_event

    def cleanup_expired_data(self):
        """Clean up expired correlation data"""
        current_time = datetime.now()

        # Clean up dedup cache
        expired_fingerprints = [
            fingerprint for fingerprint, timestamp in self.dedup_cache.items()
            if (current_time - timestamp).total_seconds() > self.dedup_ttl
        ]
        for fingerprint in expired_fingerprints:
            del self.dedup_cache[fingerprint]

        # Clean up suppression list
        expired_suppressions = [
            target for target, expiry_time in self.suppression_list.items()
            if current_time >= expiry_time
        ]
        for target in expired_suppressions:
            del self.suppression_list[target]

        # Clean up old events from windows
        window_cutoff = current_time - timedelta(seconds=self.window_seconds)
        for key in self.event_windows:
            self.event_windows[key] = deque(
                [event for event in self.event_windows[key] if event.timestamp >= window_cutoff],
                maxlen=self.max_events_per_window
            )

    def get_correlation_stats(self) -> Dict[str, Any]:
        """Get correlation statistics"""
        stats = dict(self.correlation_stats)
        stats['dedup_cache_size'] = len(self.dedup_cache)
        stats['suppression_list_size'] = len(self.suppression_list)
        stats['active_windows'] = len(self.event_windows)

        # Calculate suppression efficiency
        if stats.get('total_events', 0) > 0:
            stats['suppression_rate'] = stats.get('suppressed_events', 0) / stats['total_events']
            stats['correlation_rate'] = stats.get('correlated_events', 0) / stats['total_events']
        else:
            stats['suppression_rate'] = 0.0
            stats['correlation_rate'] = 0.0

        return stats

    def process_detection_result(self, event: Dict[str, Any], detection_result: DetectionResult) -> Optional[CorrelatedEvent]:
        """Process detection result through correlation engine"""
        try:
            # Check for suppression first
            if self.is_suppressed(event):
                self.correlation_stats['suppressed_events'] += 1
                return None

            # Check for duplicates
            if self.is_duplicate(event):
                self.correlation_stats['duplicate_events'] += 1
                return None

            # Perform correlation
            correlated_event = self.correlate_event(event, detection_result)

            # Periodic cleanup
            if self.correlation_stats['total_events'] % 100 == 0:
                self.cleanup_expired_data()

            return correlated_event

        except Exception as e:
            logger.error(f"Correlation processing failed: {e}")
            return None

    def get_active_correlations(self) -> List[Dict[str, Any]]:
        """Get currently active correlation windows"""
        active_correlations = []

        for key, events in self.event_windows.items():
            if events:
                latest_event = events[-1]
                active_correlations.append({
                    'correlation_key': key,
                    'event_count': len(events),
                    'latest_event': latest_event.timestamp.isoformat(),
                    'threat_types': list(set().union(*[event.threat_types for event in events])),
                    'max_severity': max(event.severity for event in events)
                })

        return sorted(active_correlations, key=lambda x: x['event_count'], reverse=True)