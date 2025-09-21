import yaml
import json
import os
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class ConfigManager:
    def __init__(self, config_path: str = "config.yml"):
        self.config_path = config_path
        self.config = {}
        self.load_config()

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    if self.config_path.endswith('.json'):
                        self.config = json.load(f)
                    else:
                        self.config = yaml.safe_load(f)

                logger.info(f"Configuration loaded from {self.config_path}")
            else:
                logger.warning(f"Configuration file not found: {self.config_path}")
                self.config = self.get_default_config()

        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            self.config = self.get_default_config()

        return self.config

    def save_config(self):
        """Save configuration to file"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                if self.config_path.endswith('.json'):
                    json.dump(self.config, f, indent=2, ensure_ascii=False)
                else:
                    yaml.dump(self.config, f, default_flow_style=False, allow_unicode=True)

            logger.info(f"Configuration saved to {self.config_path}")

        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")

    def update_config(self, updates: Dict[str, Any]):
        """Update configuration with new values"""
        self._deep_update(self.config, updates)
        self.save_config()

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: Any):
        """Set configuration value"""
        keys = key.split('.')
        config = self.config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

    def _deep_update(self, base_dict: Dict[str, Any], update_dict: Dict[str, Any]):
        """Deep update dictionary"""
        for key, value in update_dict.items():
            if isinstance(value, dict) and key in base_dict and isinstance(base_dict[key], dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'system': {
                'max_line_length': 1048576,
                'max_decode_rounds': 5,
                'timezone': 'UTC',
                'concurrent_workers': 4,
                'rate_limit_rps': 10000,
                'log_level': 'INFO'
            },
            'parser': {
                'allowed_encodings': ['utf-8', 'gbk', 'ascii'],
                'skip_empty_lines': True,
                'skip_bom': True
            },
            'detector': {
                'rules_file': 'rules.yml',
                'ml_model_path': 'models/',
                'anomaly_window': 3600,
                'ml_threshold': 0.8,
                'enable_ml': True
            },
            'correlator': {
                'window_seconds': 60,
                'dedup_ttl': 600,
                'max_events_per_window': 100
            },
            'responder': {
                'action_timeout': 5,
                'max_actions_per_second': 100
            },
            'output': {
                'signals_file': 'out/signals.jsonl',
                'actions_file': 'out/actions.jsonl',
                'metrics_file': 'out/metrics.json'
            },
            'masking': {
                'email_pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'phone_pattern': r'\b1[3-9]\d{9}\b',
                'id_card_pattern': r'\b\d{17}[\dXx]\b',
                'credit_card_pattern': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
                'api_key_pattern': r'\b[A-Za-z0-9]{32,}\b'
            },
            'rules': {
                'sqli': [
                    {
                        'pattern': r'(?i)(union\s+select|select\s+.*\s+from\s+.*\s+where|insert\s+into|delete\s+from|update\s+.*\s+set)',
                        'severity': 'high',
                        'enabled': True
                    },
                    {
                        'pattern': r'(?i)(drop\s+table|alter\s+table|create\s+table|truncate\s+table)',
                        'severity': 'critical',
                        'enabled': True
                    }
                ],
                'xss': [
                    {
                        'pattern': r'(?i)(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\()',
                        'severity': 'medium',
                        'enabled': True
                    },
                    {
                        'pattern': r'(?i)(<iframe|<object|<embed|document\.|window\.)',
                        'severity': 'high',
                        'enabled': True
                    }
                ],
                'command_injection': [
                    {
                        'pattern': r'(?i)(;|\||&|\$\(|`|nc\s|netcat|curl\s|wget\s)',
                        'severity': 'high',
                        'enabled': True
                    },
                    {
                        'pattern': r'(?i)(/bin/|/usr/|cmd\.exe|powershell)',
                        'severity': 'critical',
                        'enabled': True
                    }
                ]
            }
        }

    def reload_config(self):
        """Reload configuration from file"""
        old_config = self.config.copy()
        self.load_config()

        # Check for significant changes
        changes = self._detect_changes(old_config, self.config)
        if changes:
            logger.info(f"Configuration reloaded with changes: {changes}")

    def _detect_changes(self, old_config: Dict[str, Any], new_config: Dict[str, Any]) -> Dict[str, Any]:
        """Detect changes between configurations"""
        changes = {}

        for key, new_value in new_config.items():
            if key not in old_config:
                changes[key] = {'type': 'added', 'value': new_value}
            elif old_config[key] != new_value:
                changes[key] = {'type': 'modified', 'old_value': old_config[key], 'new_value': new_value}

        for key in old_config:
            if key not in new_config:
                changes[key] = {'type': 'removed', 'old_value': old_config[key]}

        return changes

    def validate_config(self) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []

        # Check required sections
        required_sections = ['system', 'parser', 'detector', 'correlator', 'responder', 'output']
        for section in required_sections:
            if section not in self.config:
                errors.append(f"Missing required section: {section}")

        # Validate numeric values
        if 'system' in self.config:
            system = self.config['system']
            if 'max_line_length' in system and not isinstance(system['max_line_length'], int):
                errors.append("system.max_line_length must be an integer")
            if 'max_decode_rounds' in system and not isinstance(system['max_decode_rounds'], int):
                errors.append("system.max_decode_rounds must be an integer")

        # Validate paths
        output = self.config.get('output', {})
        for file_key in ['signals_file', 'actions_file', 'metrics_file']:
            if file_key in output:
                file_path = output[file_key]
                if not isinstance(file_path, str):
                    errors.append(f"output.{file_key} must be a string")

        # Validate rules
        rules = self.config.get('rules', {})
        for category, rule_list in rules.items():
            if not isinstance(rule_list, list):
                errors.append(f"rules.{category} must be a list")
                continue

            for i, rule in enumerate(rule_list):
                if not isinstance(rule, dict):
                    errors.append(f"rules.{category}[{i}] must be a dictionary")
                    continue

                if 'pattern' not in rule:
                    errors.append(f"rules.{category}[{i}] missing required 'pattern' field")

        return errors

    def get_tenant_config(self, tenant: str) -> Dict[str, Any]:
        """Get tenant-specific configuration"""
        tenant_config = self.config.get('tenants', {}).get(tenant, {})
        return tenant_config

    def merge_tenant_config(self, tenant: str) -> Dict[str, Any]:
        """Merge tenant-specific config with global config"""
        base_config = self.config.copy()
        tenant_config = self.get_tenant_config(tenant)

        if tenant_config:
            self._deep_update(base_config, tenant_config)

        return base_config