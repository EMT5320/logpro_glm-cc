import re
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set
import ipaddress
import uuid

logger = logging.getLogger(__name__)

class LogNormalizer:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.setup_masking_patterns()
        self.setup_ip_normalization()

    def setup_masking_patterns(self):
        """Setup patterns for PII and sensitive data masking"""
        self.masking_patterns = self.config.get('masking', {})

    def setup_ip_normalization(self):
        """Setup IP normalization rules"""
        self.private_ip_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('127.0.0.0/8')
        ]

    def normalize_timestamp(self, ts: Any) -> Optional[str]:
        """Normalize timestamp to ISO8601 UTC format"""
        if not ts:
            return None

        try:
            if isinstance(ts, str):
                # Handle various timestamp formats
                ts = ts.strip()
                if ts.endswith('Z'):
                    ts = ts[:-1] + '+00:00'
                elif '+' not in ts and '-' not in ts[10:]:
                    ts += '+00:00'

                # Parse with datetime.fromisoformat for ISO format
                try:
                    dt = datetime.fromisoformat(ts)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt.isoformat()
                except ValueError:
                    # Fallback to other formats
                    for fmt in [
                        '%Y-%m-%d %H:%M:%S',
                        '%Y-%m-%dT%H:%M:%S',
                        '%d/%b/%Y:%H:%M:%S',
                        '%b %d %H:%M:%S'
                    ]:
                        try:
                            dt = datetime.strptime(ts, fmt)
                            dt = dt.replace(tzinfo=timezone.utc)
                            return dt.isoformat()
                        except ValueError:
                            continue

            elif isinstance(ts, datetime):
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                return ts.isoformat()

        except Exception as e:
            logger.warning(f"Failed to normalize timestamp {ts}: {e}")

        return None

    def normalize_ip(self, ip_str: str) -> Optional[str]:
        """Normalize IP address"""
        if not ip_str:
            return None

        try:
            # Remove port if present
            if ':' in ip_str and '.' in ip_str:
                ip_str = ip_str.split(':')[0]

            ip = ipaddress.ip_address(ip_str.strip())
            return str(ip)
        except ValueError:
            return None

    def normalize_severity(self, severity: Any) -> str:
        """Normalize severity levels"""
        severity_map = {
            'critical': ['critical', 'crit', 'fatal', 'emerg'],
            'high': ['high', 'error', 'err', 'alert'],
            'medium': ['medium', 'warning', 'warn'],
            'low': ['low', 'info', 'information', 'debug']
        }

        if not severity:
            return 'medium'

        severity_lower = str(severity).lower()

        for normalized_level, variations in severity_map.items():
            if severity_lower in variations:
                return normalized_level

        # Default mapping based on keywords
        if any(keyword in severity_lower for keyword in ['crit', 'fatal', 'emerg']):
            return 'critical'
        elif any(keyword in severity_lower for keyword in ['error', 'err']):
            return 'high'
        elif any(keyword in severity_lower for keyword in ['warn', 'warning']):
            return 'medium'
        else:
            return 'low'

    def extract_user_agent_info(self, user_agent: str) -> Dict[str, str]:
        """Extract browser and OS info from user agent"""
        if not user_agent:
            return {}

        info = {}
        ua_lower = user_agent.lower()

        # Browser detection
        if 'chrome' in ua_lower and 'edg' not in ua_lower:
            info['browser'] = 'Chrome'
        elif 'firefox' in ua_lower:
            info['browser'] = 'Firefox'
        elif 'safari' in ua_lower and 'chrome' not in ua_lower:
            info['browser'] = 'Safari'
        elif 'edg' in ua_lower:
            info['browser'] = 'Edge'
        elif 'opera' in ua_lower:
            info['browser'] = 'Opera'

        # OS detection
        if 'windows' in ua_lower:
            info['os'] = 'Windows'
        elif 'mac' in ua_lower or 'osx' in ua_lower:
            info['os'] = 'macOS'
        elif 'linux' in ua_lower:
            info['os'] = 'Linux'
        elif 'android' in ua_lower:
            info['os'] = 'Android'
        elif 'ios' in ua_lower or 'iphone' in ua_lower or 'ipad' in ua_lower:
            info['os'] = 'iOS'

        return info

    def extract_geolocation(self, ip: str) -> Dict[str, str]:
        """Extract basic geolocation (placeholder - would integrate with GeoIP DB)"""
        if not ip:
            return {}

        # Basic geolocation simulation
        geo_info = {}

        try:
            ip_obj = ipaddress.ip_address(ip)

            # Check if private IP
            for private_range in self.private_ip_ranges:
                if ip_obj in private_range:
                    geo_info = {
                        'country': 'Private',
                        'region': 'Internal Network',
                        'city': 'Local'
                    }
                    return geo_info

            # Placeholder for public IPs - would integrate with GeoIP database
            geo_info = {
                'country': 'Unknown',
                'region': 'Unknown',
                'city': 'Unknown'
            }

        except ValueError:
            pass

        return geo_info

    def mask_sensitive_data(self, text: str, mask_char: str = '*') -> str:
        """Mask PII and sensitive data in text"""
        if not text:
            return text

        masked_text = text
        masked_fields = []

        # Email masking
        if 'email_pattern' in self.masking_patterns:
            email_pattern = re.compile(self.masking_patterns['email_pattern'])
            masked_text, email_count = email_pattern.subn(
                lambda m: m.group(0)[0] + mask_char * (len(m.group(0)) - len(m.group(0).split('@')[1]) - 1) +
                         '@' + mask_char * len(m.group(0).split('@')[1].split('.')[0]) +
                         '.' + m.group(0).split('.')[-1],
                masked_text
            )
            if email_count > 0:
                masked_fields.append('email')

        # Phone masking
        if 'phone_pattern' in self.masking_patterns:
            phone_pattern = re.compile(self.masking_patterns['phone_pattern'])
            masked_text, phone_count = phone_pattern.subn(
                lambda m: m.group(0)[:3] + mask_char * 4 + m.group(0)[7:],
                masked_text
            )
            if phone_count > 0:
                masked_fields.append('phone')

        # ID card masking
        if 'id_card_pattern' in self.masking_patterns:
            id_pattern = re.compile(self.masking_patterns['id_card_pattern'])
            masked_text, id_count = id_pattern.subn(
                lambda m: m.group(0)[:6] + mask_char * 8 + m.group(0)[-1],
                masked_text
            )
            if id_count > 0:
                masked_fields.append('id_card')

        # Credit card masking
        if 'credit_card_pattern' in self.masking_patterns:
            cc_pattern = re.compile(self.masking_patterns['credit_card_pattern'])
            masked_text, cc_count = cc_pattern.subn(
                lambda m: mask_char * 12 + m.group(0)[-4:],
                masked_text
            )
            if cc_count > 0:
                masked_fields.append('credit_card')

        # API key masking
        if 'api_key_pattern' in self.masking_patterns:
            api_pattern = re.compile(self.masking_patterns['api_key_pattern'])
            masked_text, api_count = api_pattern.subn(
                lambda m: mask_char * min(len(m.group(0)), 8),
                masked_text
            )
            if api_count > 0:
                masked_fields.append('api_key')

        return masked_text

    def normalize_request_method(self, method: Any) -> str:
        """Normalize HTTP request method"""
        if not method:
            return 'UNKNOWN'

        method_str = str(method).upper()
        valid_methods = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE'}

        return method_str if method_str in valid_methods else 'UNKNOWN'

    def normalize_status_code(self, status_code: Any) -> Optional[int]:
        """Normalize HTTP status code"""
        if not status_code:
            return None

        try:
            code = int(status_code)
            if 100 <= code <= 599:
                return code
        except (ValueError, TypeError):
            pass

        return None

    def normalize_path(self, path: str) -> str:
        """Normalize URL path"""
        if not path:
            return '/'

        # Remove multiple slashes
        path = re.sub(r'/+', '/', path)

        # Remove trailing slash unless it's the root
        if len(path) > 1 and path.endswith('/'):
            path = path.rstrip('/')

        return path or '/'

    def extract_query_parameters(self, query: str) -> Dict[str, str]:
        """Extract and normalize query parameters"""
        if not query:
            return {}

        params = {}
        try:
            from urllib.parse import parse_qs
            parsed = parse_qs(query)
            for key, values in parsed.items():
                params[key] = values[0] if values else ''
        except Exception:
            pass

        return params

    def normalize_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize raw event to standard format"""
        normalized = {
            'event_id': raw_event.get('event_id', str(uuid.uuid4())),
            'timestamp': self.normalize_timestamp(raw_event.get('timestamp')),
            'tenant': raw_event.get('tenant', 'default'),
            'source_ip': self.normalize_ip(raw_event.get('source_ip') or raw_event.get('remote_addr')),
            'severity': self.normalize_severity(raw_event.get('level') or raw_event.get('severity')),
            'original_format': raw_event.get('parsed_format', 'unknown'),
            'line_number': raw_event.get('line_number')
        }

        # Extract and normalize message
        message = raw_event.get('message', '')
        if 'decoded_query' in raw_event:
            message = raw_event['decoded_query']
        elif 'query' in raw_event:
            message = raw_event['query']
        elif 'request' in raw_event and isinstance(raw_event['request'], str):
            message = raw_event['request']

        # Mask sensitive data in message
        masked_message = self.mask_sensitive_data(message)
        normalized['message'] = masked_message

        # HTTP-specific normalization
        if any(key in raw_event for key in ['method', 'path', 'status_code', 'user_agent']):
            normalized.update({
                'http_method': self.normalize_request_method(raw_event.get('method')),
                'http_path': self.normalize_path(raw_event.get('path')),
                'http_status': self.normalize_status_code(raw_event.get('status_code')),
                'http_user_agent': raw_event.get('user_agent'),
                'http_referer': raw_event.get('referer')
            })

            # Extract user agent info
            if normalized['http_user_agent']:
                normalized['user_agent_info'] = self.extract_user_agent_info(normalized['http_user_agent'])

            # Extract query parameters
            if 'query' in raw_event:
                normalized['query_params'] = self.extract_query_parameters(raw_event['query'])

        # Database-specific normalization
        if any(key in raw_event for key in ['operation', 'database', 'user']):
            normalized.update({
                'db_operation': raw_event.get('operation'),
                'db_name': raw_event.get('database'),
                'db_user': raw_event.get('user')
            })

        # Cloud audit normalization
        if any(key in raw_event for key in ['action', 'resource', 'role']):
            normalized.update({
                'cloud_action': raw_event.get('action'),
                'cloud_resource': raw_event.get('resource'),
                'cloud_role': raw_event.get('role'),
                'cloud_result': raw_event.get('result')
            })

        # Container normalization
        if any(key in raw_event for key in ['pod', 'container']):
            normalized.update({
                'container_pod': raw_event.get('pod'),
                'container_name': raw_event.get('container')
            })

        # Add geolocation info
        if normalized['source_ip']:
            normalized['geolocation'] = self.extract_geolocation(normalized['source_ip'])

        # Add masked fields info
        normalized['masked_fields'] = []

        # Copy over any additional fields that might be useful
        additional_fields = {
            'bytes_sent': raw_event.get('bytes_sent'),
            'remote_user': raw_event.get('remote_user') or raw_event.get('user'),
            'correlation_id': raw_event.get('correlation_id'),
            'session_id': raw_event.get('session_id'),
            'request_id': raw_event.get('request_id')
        }

        for key, value in additional_fields.items():
            if value is not None:
                normalized[key] = value

        # Remove None values
        normalized = {k: v for k, v in normalized.items() if v is not None}

        return normalized

    def normalize_batch(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize a batch of events"""
        normalized_events = []

        for event in events:
            try:
                normalized = self.normalize_event(event)
                normalized_events.append(normalized)
            except Exception as e:
                logger.error(f"Failed to normalize event: {e}")
                continue

        return normalized_events