import re
import json
import gzip
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Iterator, Union
from urllib.parse import unquote, unquote_plus
import codecs
import uuid
import yaml

logger = logging.getLogger(__name__)

class LogParser:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.setup_patterns()

    def setup_patterns(self):
        """Setup regex patterns for different log formats"""
        self.patterns = {
            'nginx_combined': re.compile(
                r'(?P<remote_addr>\S+) - (?P<remote_user>\S+) \[(?P<time_local>[^\]]+)\] '
                r'"(?P<request>[^"]*)" (?P<status>\d+) (?P<body_bytes_sent>\d+) '
                r'"(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"'
            ),
            'apache_common': re.compile(
                r'(?P<remote_addr>\S+) - (?P<remote_user>\S+) \[(?P<time_local>[^\]]+)\] '
                r'"(?P<request>[^"]*)" (?P<status>\d+) (?P<body_bytes_sent>\d+)'
            ),
            'json_log': re.compile(r'^\s*\{.*\}\s*$'),
            'cloud_audit': re.compile(
                r'(?P<timestamp>[^\s]+)\s+(?P<user>[^\s]+)\s+(?P<role>[^\s]+)\s+'
                r'(?P<resource>[^\s]+)\s+(?P<action>[^\s]+)\s+(?P<result>[^\s]+)'
            ),
            'container_log': re.compile(
                r'(?P<timestamp>[^\s]+)\s+(?P<level>\w+)\s+(?P<pod>[^\s]+)\s+'
                r'(?P<container>[^\s]+)\s+(?P<message>.*)'
            ),
            'database_audit': re.compile(
                r'(?P<timestamp>[^\s]+)\s+(?P<user>[^\s]+)\s+(?P<db>[^\s]+)\s+'
                r'(?P<operation>[^\s]+)\s+(?P<query>.*)'
            )
        }

        # Common timestamp formats
        self.timestamp_formats = [
            '%d/%b/%Y:%H:%M:%S %z',
            '%d/%b/%Y:%H:%M:%S',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S'
        ]

    def detect_format(self, line: str) -> str:
        """Detect log format from a sample line"""
        line = line.strip()

        if not line:
            return 'empty'

        # Check for JSON format
        if self.patterns['json_log'].match(line):
            try:
                json.loads(line)
                return 'json'
            except json.JSONDecodeError:
                pass

        # Check for nginx/apache formats
        if self.patterns['nginx_combined'].match(line):
            return 'nginx_combined'
        elif self.patterns['apache_common'].match(line):
            return 'apache_common'

        # Check for cloud audit
        if self.patterns['cloud_audit'].match(line):
            return 'cloud_audit'

        # Check for container logs
        if self.patterns['container_log'].match(line):
            return 'container'

        # Check for database audit
        if self.patterns['database_audit'].match(line):
            return 'database_audit'

        return 'raw'

    def parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse timestamp using various formats"""
        for fmt in self.timestamp_formats:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                if dt.tzinfo is None:
                    # Apply timezone from config
                    timezone = self.config.get('system', {}).get('timezone', 'UTC')
                    # For simplicity, assume UTC for now
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                return dt
            except ValueError:
                continue
        return None

    def decode_line(self, line: bytes) -> str:
        """Decode line with multiple encoding attempts"""
        encodings = self.config.get('parser', {}).get('allowed_encodings', ['utf-8', 'gbk', 'ascii'])

        for encoding in encodings:
            try:
                # Skip BOM if present
                if line.startswith(codecs.BOM_UTF8):
                    line = line[3:]
                return line.decode(encoding)
            except UnicodeDecodeError:
                continue

        # Fallback: replace invalid characters
        return line.decode('utf-8', errors='replace')

    def sanitize_input(self, line: str) -> str:
        """Sanitize input line"""
        # Remove null bytes and other control characters
        line = line.replace('\x00', '')
        line = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', line)
        return line.strip()

    def decode_obfuscation(self, text: str, max_rounds: int = 5) -> str:
        """Multi-round decoding to handle obfuscation"""
        result = text
        rounds = 0

        while rounds < max_rounds:
            original = result

            # URL decoding
            if '%' in result:
                result = unquote_plus(result)

            # Base64-like patterns (simple heuristic)
            if re.match(r'^[A-Za-z0-9+/=]+$', result) and len(result) % 4 == 0:
                try:
                    import base64
                    decoded = base64.b64decode(result).decode('utf-8', errors='ignore')
                    if len(decoded) > 0 and decoded != result:
                        result = decoded
                except:
                    pass

            # Hex decoding
            if re.match(r'^[0-9a-fA-F]+$', result) and len(result) % 2 == 0:
                try:
                    decoded = bytes.fromhex(result).decode('utf-8', errors='ignore')
                    if len(decoded) > 0 and decoded != result:
                        result = decoded
                except:
                    pass

            # Check if we made progress
            if result == original:
                break

            rounds += 1

        return result

    def parse_json_log(self, line: str) -> Dict[str, Any]:
        """Parse JSON log entry"""
        try:
            data = json.loads(line)

            # Extract common fields
            result = {
                'timestamp': data.get('timestamp') or data.get('@timestamp') or data.get('time'),
                'level': data.get('level') or data.get('severity'),
                'message': data.get('message') or data.get('msg'),
                'source_ip': data.get('src_ip') or data.get('client_ip') or data.get('remote_addr'),
                'user_agent': data.get('user_agent') or data.get('http_user_agent'),
                'method': data.get('method'),
                'path': data.get('path') or data.get('url'),
                'status_code': data.get('status') or data.get('status_code'),
                'tenant': data.get('tenant') or data.get('organization') or 'default'
            }

            # Handle nested structures
            if 'request' in data and isinstance(data['request'], dict):
                result.update({
                    'method': data['request'].get('method'),
                    'path': data['request'].get('path'),
                    'query': data['request'].get('query_string')
                })

            # Parse timestamp
            if result['timestamp']:
                if isinstance(result['timestamp'], str):
                    parsed_ts = self.parse_timestamp(result['timestamp'])
                    if parsed_ts:
                        result['timestamp'] = parsed_ts.isoformat()

            return {k: v for k, v in result.items() if v is not None}

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON: {e}")
            return {'message': line, 'parse_error': str(e)}

    def parse_nginx_log(self, line: str, format_type: str = 'combined') -> Dict[str, Any]:
        """Parse Nginx log entry"""
        if format_type == 'combined':
            match = self.patterns['nginx_combined'].match(line)
        else:
            match = self.patterns['apache_common'].match(line)

        if not match:
            return {'message': line, 'parse_error': 'Pattern mismatch'}

        data = match.groupdict()

        # Parse request
        request = data.get('request', '')
        method, path, query = '', '', ''
        if ' ' in request:
            parts = request.split(' ')
            method = parts[0] if len(parts) > 0 else ''
            path = parts[1] if len(parts) > 1 else ''
            if '?' in path:
                path, query = path.split('?', 1)

        # Parse timestamp
        timestamp = self.parse_timestamp(data.get('time_local', ''))

        return {
            'timestamp': timestamp.isoformat() if timestamp else None,
            'source_ip': data.get('remote_addr'),
            'user': data.get('remote_user'),
            'method': method,
            'path': path,
            'query': query,
            'status_code': int(data.get('status', 0)) if data.get('status', '').isdigit() else None,
            'bytes_sent': int(data.get('body_bytes_sent', 0)) if data.get('body_bytes_sent', '').isdigit() else None,
            'referer': data.get('http_referer'),
            'user_agent': data.get('http_user_agent'),
            'tenant': 'default'
        }

    def parse_cloud_audit(self, line: str) -> Dict[str, Any]:
        """Parse cloud audit log entry"""
        match = self.patterns['cloud_audit'].match(line)
        if not match:
            return {'message': line, 'parse_error': 'Pattern mismatch'}

        data = match.groupdict()
        timestamp = self.parse_timestamp(data.get('timestamp', ''))

        return {
            'timestamp': timestamp.isoformat() if timestamp else None,
            'user': data.get('user'),
            'role': data.get('role'),
            'resource': data.get('resource'),
            'action': data.get('action'),
            'result': data.get('result'),
            'message': line,
            'tenant': 'default'
        }

    def parse_container_log(self, line: str) -> Dict[str, Any]:
        """Parse container log entry"""
        match = self.patterns['container_log'].match(line)
        if not match:
            return {'message': line, 'parse_error': 'Pattern mismatch'}

        data = match.groupdict()
        timestamp = self.parse_timestamp(data.get('timestamp', ''))

        # Extract IP addresses from message
        message = data.get('message', '')
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)

        return {
            'timestamp': timestamp.isoformat() if timestamp else None,
            'level': data.get('level'),
            'pod': data.get('pod'),
            'container': data.get('container'),
            'message': message,
            'source_ip': ip_match.group() if ip_match else None,
            'tenant': 'default'
        }

    def parse_database_audit(self, line: str) -> Dict[str, Any]:
        """Parse database audit log entry"""
        match = self.patterns['database_audit'].match(line)
        if not match:
            return {'message': line, 'parse_error': 'Pattern mismatch'}

        data = match.groupdict()
        timestamp = self.parse_timestamp(data.get('timestamp', ''))
        query = data.get('query', '')

        # Apply de-obfuscation to SQL queries
        decoded_query = self.decode_obfuscation(query)

        return {
            'timestamp': timestamp.isoformat() if timestamp else None,
            'user': data.get('user'),
            'database': data.get('db'),
            'operation': data.get('operation'),
            'query': query,
            'decoded_query': decoded_query,
            'message': line,
            'tenant': 'default'
        }

    def parse_line(self, line: str) -> Dict[str, Any]:
        """Parse a single log line"""
        # Basic sanitization
        line = self.sanitize_input(line)
        if not line:
            return {}

        # Detect format
        format_type = self.detect_format(line)

        # Parse based on format
        if format_type == 'json':
            result = self.parse_json_log(line)
        elif format_type in ['nginx_combined', 'apache_common']:
            result = self.parse_nginx_log(line, format_type)
        elif format_type == 'cloud_audit':
            result = self.parse_cloud_audit(line)
        elif format_type == 'container':
            result = self.parse_container_log(line)
        elif format_type == 'database_audit':
            result = self.parse_database_audit(line)
        else:
            result = {'message': line, 'format': format_type}

        # Add parsing metadata
        result['event_id'] = str(uuid.uuid4())
        result['parsed_format'] = format_type

        return result

    def parse_file(self, file_path: str) -> Iterator[Dict[str, Any]]:
        """Parse log file with support for .gz files"""
        max_line_length = self.config.get('system', {}).get('max_line_length', 1048576)

        if file_path.endswith('.gz'):
            opener = gzip.open
        else:
            opener = open

        try:
            with opener(file_path, 'rb') as f:
                for line_num, line_bytes in enumerate(f, 1):
                    # Check line length
                    if len(line_bytes) > max_line_length:
                        logger.warning(f"Line {line_num} too long, skipping")
                        continue

                    # Decode line
                    try:
                        line = self.decode_line(line_bytes)
                    except Exception as e:
                        logger.warning(f"Failed to decode line {line_num}: {e}")
                        continue

                    # Skip empty lines if configured
                    if not line.strip() and self.config.get('parser', {}).get('skip_empty_lines', True):
                        continue

                    # Parse line
                    try:
                        parsed = self.parse_line(line)
                        if parsed:
                            parsed['line_number'] = line_num
                            yield parsed
                    except Exception as e:
                        logger.warning(f"Failed to parse line {line_num}: {e}")
                        continue

        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            raise

    def parse_stream(self, stream) -> Iterator[Dict[str, Any]]:
        """Parse log entries from a stream"""
        max_line_length = self.config.get('system', {}).get('max_line_length', 1048576)

        for line_num, line_bytes in enumerate(stream, 1):
            # Check line length
            if len(line_bytes) > max_line_length:
                logger.warning(f"Line {line_num} too long, skipping")
                continue

            # Decode line
            try:
                line = self.decode_line(line_bytes)
            except Exception as e:
                logger.warning(f"Failed to decode line {line_num}: {e}")
                continue

            # Skip empty lines if configured
            if not line.strip() and self.config.get('parser', {}).get('skip_empty_lines', True):
                continue

            # Parse line
            try:
                parsed = self.parse_line(line)
                if parsed:
                    parsed['line_number'] = line_num
                    yield parsed
            except Exception as e:
                logger.warning(f"Failed to parse line {line_num}: {e}")
                continue