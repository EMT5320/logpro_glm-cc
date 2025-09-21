#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import pandas as pd
import numpy as np
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

class LogGrader:
    def __init__(self, working_dir: str = "."):
        self.working_dir = working_dir
        self.results = {
            'correctness': {},
            'performance': {},
            'comparison': {},
            'summary': {}
        }

    def run_command(self, cmd: List[str], timeout: int = 300) -> Tuple[bool, str, str]:
        """Run command with timeout and return result"""
        try:
            result = subprocess.run(
                cmd,
                cwd=self.working_dir,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)

    def parse_signals_jsonl(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse signals.jsonl file"""
        signals = []
        if not os.path.exists(file_path):
            return signals

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            signal = json.loads(line)
                            signals.append(signal)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            print(f"Error parsing signals file: {e}")

        return signals

    def parse_actions_jsonl(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse actions.jsonl file"""
        actions = []
        if not os.path.exists(file_path):
            return actions

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            action = json.loads(line)
                            actions.append(action)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            print(f"Error parsing actions file: {e}")

        return actions

    def parse_metrics_json(self, file_path: str) -> Dict[str, Any]:
        """Parse metrics.json file"""
        if not os.path.exists(file_path):
            return {}

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error parsing metrics file: {e}")
            return {}

    def generate_test_data_with_labels(self, count: int = 1000, seed: int = 42) -> Tuple[List[str], List[Dict[str, Any]]]:
        """Generate test data with ground truth labels"""
        # Use the sample generator to create labeled data
        cmd = [sys.executable, 'samples/generator.py', '--seed', str(seed), '--count', str(count)]
        success, stdout, stderr = self.run_command(cmd)

        if not success:
            print(f"Failed to generate test data: {stderr}")
            return [], []

        # Parse generated logs and create labels based on content
        logs = stdout.strip().split('\n')
        labels = []

        for i, log in enumerate(logs):
            label = {
                'line_number': i + 1,
                'is_attack': False,
                'attack_types': [],
                'expected_severity': 'low',
                'expected_actions': []
            }

            # Simple detection logic for labeling
            log_lower = log.lower()

            if any(pattern in log_lower for pattern in [
                'union select', 'or 1=1', 'drop table', 'insert into', 'delete from'
            ]):
                label['is_attack'] = True
                label['attack_types'].append('sqli')
                label['expected_severity'] = 'high'
                label['expected_actions'].extend(['block_ip', 'redact_log'])

            elif any(pattern in log_lower for pattern in [
                '<script', 'javascript:', 'onerror=', 'alert(', 'document.', 'window.'
            ]):
                label['is_attack'] = True
                label['attack_types'].append('xss')
                label['expected_severity'] = 'medium'
                label['expected_actions'].extend(['throttle_ip', 'notify'])

            elif any(pattern in log_lower for pattern in [
                '../', 'etc/passwd', '..\\', 'file://', 'phar://'
            ]):
                label['is_attack'] = True
                label['attack_types'].append('path_traversal')
                label['expected_severity'] = 'high'
                label['expected_actions'].extend(['block_ip'])

            elif any(pattern in log_lower for pattern in [
                ';', '|', '&', '$(', '`', 'nc ', 'netcat', 'cmd.exe'
            ]):
                label['is_attack'] = True
                label['attack_types'].append('command_injection')
                label['expected_severity'] = 'critical'
                label['expected_actions'].extend(['block_ip', 'revoke_token'])

            elif any(pattern in log_lower for pattern in [
                'localhost', '127.0.0.1', '169.254.169.254'
            ]) and any(pattern in log_lower for pattern in ['url=', 'fetch', 'proxy']):
                label['is_attack'] = True
                label['attack_types'].append('ssrf')
                label['expected_severity'] = 'high'
                label['expected_actions'].extend(['block_ip'])

            elif any(pattern in log_lower for pattern in [
                '${jndi:', 'ldap://', 'rmi://', 'dns://'
            ]):
                label['is_attack'] = True
                label['attack_types'].append('log4shell')
                label['expected_severity'] = 'critical'
                label['expected_actions'].extend(['block_ip', 'redact_log'])

            labels.append(label)

        return logs, labels

    def evaluate_correctness(self, test_file: str) -> Dict[str, Any]:
        """Evaluate detection correctness"""
        print("Evaluating detection correctness...")

        # Run the analyzer
        cmd = [sys.executable, 'src/main.py', 'analyze', '--file', test_file, '--mode', 'balanced']
        success, stdout, stderr = self.run_command(cmd)

        if not success:
            print(f"Failed to run analyzer: {stderr}")
            return {'error': f"Analysis failed: {stderr}"}

        # Generate ground truth labels
        test_logs, ground_truth = self.generate_test_data_with_labels(count=1000, seed=42)

        # Parse results
        signals = self.parse_signals_jsonl('out/signals.jsonl')
        actions = self.parse_actions_jsonl('out/actions.jsonl')
        metrics = self.parse_metrics_json('out/metrics.json')

        # Convert signals to detection results
        detections = {}
        for signal in signals:
            detections[signal['event_id']] = {
                'threat_types': signal['threat_types'],
                'severity': signal['severity'],
                'actions': signal.get('action_planned', [])
            }

        # Calculate correctness metrics
        y_true = []
        y_pred = []

        # Match detections with ground truth
        detected_attacks = set()
        for label in ground_truth:
            y_true.append(1 if label['is_attack'] else 0)

            # Simple matching based on line number and content
            is_detected = False
            for signal in signals:
                if 'sanitized_excerpt' in signal and label['line_number']:
                    # This is a simplified matching - in real implementation would use better correlation
                    if any(attack_type in signal['threat_types'] for attack_type in label['attack_types']):
                        is_detected = True
                        detected_attacks.add(label['line_number'])
                        break

            y_pred.append(1 if is_detected else 0)

        # Calculate metrics
        if len(y_true) > 0:
            precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='weighted')
            accuracy = accuracy_score(y_true, y_pred)

            # Focus on high/critical events
            high_severity_true = []
            high_severity_pred = []

            for i, label in enumerate(ground_truth):
                if label['expected_severity'] in ['high', 'critical']:
                    high_severity_true.append(1 if label['is_attack'] else 0)
                    is_detected_high = y_pred[i] == 1 and label['expected_severity'] in ['high', 'critical']
                    high_severity_pred.append(1 if is_detected_high else 0)

            if len(high_severity_true) > 0:
                high_precision, high_recall, high_f1, _ = precision_recall_fscore_support(
                    high_severity_true, high_severity_pred, average='weighted', zero_division=0
                )
            else:
                high_precision = high_recall = high_f1 = 0.0

            results = {
                'total_samples': len(y_true),
                'true_positives': sum(1 for true, pred in zip(y_true, y_pred) if true == 1 and pred == 1),
                'false_positives': sum(1 for true, pred in zip(y_true, y_pred) if true == 0 and pred == 1),
                'false_negatives': sum(1 for true, pred in zip(y_true, y_pred) if true == 1 and pred == 0),
                'true_negatives': sum(1 for true, pred in zip(y_true, y_pred) if true == 0 and pred == 0),
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'high_critical_precision': high_precision,
                'high_critical_recall': high_recall,
                'high_critical_f1': high_f1,
                'detection_rate': len(detected_attacks) / sum(1 for label in ground_truth if label['is_attack']) if sum(1 for label in ground_truth if label['is_attack']) > 0 else 0,
                'false_positive_rate': sum(1 for true, pred in zip(y_true, y_pred) if true == 0 and pred == 1) / sum(1 for true in y_true if true == 0) if sum(1 for true in y_true if true == 0) > 0 else 0
            }
        else:
            results = {'error': 'No valid samples for evaluation'}

        return results

    def evaluate_performance(self, test_file: str) -> Dict[str, Any]:
        """Evaluate system performance"""
        print("Evaluating system performance...")

        # Clean up previous output
        for output_file in ['out/signals.jsonl', 'out/actions.jsonl', 'out/metrics.json']:
            if os.path.exists(output_file):
                os.remove(output_file)

        # Run performance test
        start_time = time.time()
        cmd = [sys.executable, 'src/main.py', 'analyze', '--file', test_file, '--mode', 'balanced']
        success, stdout, stderr = self.run_command(cmd)

        end_time = time.time()
        execution_time = end_time - start_time

        if not success:
            return {'error': f"Performance test failed: {stderr}"}

        # Parse metrics
        metrics = self.parse_metrics_json('out/metrics.json')

        # Calculate memory usage (simplified)
        memory_usage = 0
        try:
            # This is a simplified memory check
            import psutil
            process = psutil.Process()
            memory_usage = process.memory_info().rss / 1024 / 1024  # MB
        except ImportError:
            pass

        # Calculate throughput
        total_lines = metrics.get('total_lines', 0)
        throughput = total_lines / execution_time if execution_time > 0 else 0

        # Get latency metrics
        avg_latency = metrics.get('duration_seconds', 0) / total_lines if total_lines > 0 else 0

        results = {
            'execution_time_seconds': execution_time,
            'throughput_lps': throughput,
            'avg_latency_ms_per_line': avg_latency * 1000,
            'memory_usage_mb': memory_usage,
            'total_lines_processed': total_lines,
            'threat_events_detected': metrics.get('threat_events', 0),
            'actions_taken': metrics.get('actions_taken', 0),
            'errors': metrics.get('error_count', 0)
        }

        return results

    def compare_detection_methods(self, test_file: str) -> Dict[str, Any]:
        """Compare rule-based vs hybrid detection"""
        print("Comparing detection methods...")

        modes = ['fast', 'balanced', 'accurate']
        results = {}

        for mode in modes:
            print(f"Testing mode: {mode}")

            # Clean up
            for output_file in ['out/signals.jsonl', 'out/actions.jsonl', 'out/metrics.json']:
                if os.path.exists(output_file):
                    os.remove(output_file)

            # Run with specific mode
            cmd = [sys.executable, 'src/main.py', 'analyze', '--file', test_file, '--mode', mode]
            success, stdout, stderr = self.run_command(cmd)

            if not success:
                results[mode] = {'error': f"Failed to run {mode} mode: {stderr}"}
                continue

            # Parse results
            signals = self.parse_signals_jsonl('out/signals.jsonl')
            metrics = self.parse_metrics_json('out/metrics.json')

            mode_results = {
                'total_signals': len(signals),
                'execution_time': metrics.get('duration_seconds', 0),
                'threat_events': metrics.get('threat_events', 0),
                'rule_hits': metrics.get('rule_hits', 0),
                'throughput': metrics.get('throughput_lps', 0),
                'memory_usage': metrics.get('rss_mb_peak', 0)
            }

            results[mode] = mode_results

        return results

    def generate_report(self, test_file: str) -> Dict[str, Any]:
        """Generate comprehensive evaluation report"""
        print("Generating evaluation report...")

        # Run all evaluations
        correctness = self.evaluate_correctness(test_file)
        performance = self.evaluate_performance(test_file)
        comparison = self.compare_detection_methods(test_file)

        # Summary assessment
        summary = {
            'overall_grade': 'F',
            'meets_requirements': False,
            'strengths': [],
            'weaknesses': [],
            'recommendations': []
        }

        # Check against requirements
        meets_min_criteria = True

        # Check F1 score requirement
        if 'high_critical_f1' in correctness:
            if correctness['high_critical_f1'] >= 0.85:
                summary['strengths'].append("High/critical event detection meets F1 ≥ 0.85 requirement")
            else:
                summary['weaknesses'].append(f"High/critical F1 score {correctness['high_critical_f1']:.3f} below 0.85 threshold")
                meets_min_criteria = False

        # Check latency requirement
        if 'avg_latency_ms_per_line' in performance:
            if performance['avg_latency_ms_per_line'] <= 15:
                summary['strengths'].append("Average latency meets ≤ 15ms requirement")
            else:
                summary['weaknesses'].append(f"Average latency {performance['avg_latency_ms_per_line']:.1f}ms exceeds 15ms threshold")
                meets_min_criteria = False

        # Check memory requirement
        if 'memory_usage_mb' in performance:
            if performance['memory_usage_mb'] <= 600:
                summary['strengths'].append("Memory usage meets ≤ 600MB requirement")
            else:
                summary['weaknesses'].append(f"Memory usage {performance['memory_usage_mb']:.1f}MB exceeds 600MB threshold")
                meets_min_criteria = False

        # Check throughput requirement
        if 'throughput_lps' in performance:
            if performance['throughput_lps'] >= 5000:
                summary['strengths'].append("Throughput meets ≥ 5k lines/second requirement")
            else:
                summary['weaknesses'].append(f"Throughput {performance['throughput_lps']:.0f} lines/second below 5k threshold")
                meets_min_criteria = False

        # Generate grade
        overall_score = 0
        if 'f1_score' in correctness:
            overall_score += correctness['f1_score'] * 40  # 40% weight
        if 'throughput_lps' in performance:
            throughput_score = min(performance['throughput_lps'] / 5000 * 30, 30)  # 30% weight
            overall_score += throughput_score
        if 'avg_latency_ms_per_line' in performance:
            latency_score = max(0, (15 - performance['avg_latency_ms_per_line']) / 15 * 20)  # 20% weight
            overall_score += latency_score
        if 'memory_usage_mb' in performance:
            memory_score = max(0, (600 - performance['memory_usage_mb']) / 600 * 10)  # 10% weight
            overall_score += memory_score

        if overall_score >= 90:
            summary['overall_grade'] = 'A'
        elif overall_score >= 80:
            summary['overall_grade'] = 'B'
        elif overall_score >= 70:
            summary['overall_grade'] = 'C'
        elif overall_score >= 60:
            summary['overall_grade'] = 'D'
        else:
            summary['overall_grade'] = 'F'

        summary['meets_requirements'] = meets_min_criteria
        summary['overall_score'] = overall_score

        # Add recommendations
        if correctness.get('false_positive_rate', 0) > 0.1:
            summary['recommendations'].append("Consider tuning detection rules to reduce false positives")
        if performance.get('throughput_lps', 0) < 3000:
            summary['recommendations'].append("Optimize parsing and detection logic for better throughput")
        if performance.get('memory_usage_mb', 0) > 500:
            summary['recommendations'].append("Implement memory optimization techniques")

        self.results = {
            'correctness': correctness,
            'performance': performance,
            'comparison': comparison,
            'summary': summary,
            'timestamp': datetime.now().isoformat(),
            'test_file': test_file
        }

        return self.results

    def save_report(self, output_file: str = 'evaluation_report.json'):
        """Save evaluation report to file"""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        print(f"Evaluation report saved to {output_file}")

    def print_summary(self):
        """Print evaluation summary"""
        if not self.results:
            print("No evaluation results available")
            return

        summary = self.results.get('summary', {})

        print("\n" + "="*60)
        print("EVALUATION SUMMARY")
        print("="*60)
        print(f"Overall Grade: {summary.get('overall_grade', 'N/A')}")
        print(f"Overall Score: {summary.get('overall_score', 0):.1f}/100")
        print(f"Meets Requirements: {'Yes' if summary.get('meets_requirements', False) else 'No'}")
        print()

        # Correctness metrics
        correctness = self.results.get('correctness', {})
        if 'f1_score' in correctness:
            print("CORRECTNESS METRICS:")
            print(f"  F1 Score: {correctness['f1_score']:.3f}")
            print(f"  Precision: {correctness['precision']:.3f}")
            print(f"  Recall: {correctness['recall']:.3f}")
            print(f"  High/Critical F1: {correctness.get('high_critical_f1', 0):.3f}")
            print(f"  Detection Rate: {correctness.get('detection_rate', 0):.1%}")
            print(f"  False Positive Rate: {correctness.get('false_positive_rate', 0):.1%}")
            print()

        # Performance metrics
        performance = self.results.get('performance', {})
        if 'throughput_lps' in performance:
            print("PERFORMANCE METRICS:")
            print(f"  Throughput: {performance['throughput_lps']:.0f} lines/second")
            print(f"  Average Latency: {performance['avg_latency_ms_per_line']:.1f} ms/line")
            print(f"  Memory Usage: {performance['memory_usage_mb']:.1f} MB")
            print(f"  Execution Time: {performance['execution_time_seconds']:.1f} seconds")
            print()

        # Strengths and weaknesses
        if summary.get('strengths'):
            print("STRENGTHS:")
            for strength in summary['strengths']:
                print(f"  ✓ {strength}")
            print()

        if summary.get('weaknesses'):
            print("WEAKNESSES:")
            for weakness in summary['weaknesses']:
                print(f"  ✗ {weakness}")
            print()

        if summary.get('recommendations'):
            print("RECOMMENDATIONS:")
            for rec in summary['recommendations']:
                print(f"  • {rec}")
            print()

        print("="*60)

def main():
    parser = argparse.ArgumentParser(description="Grade log risk detection system")
    parser.add_argument('--file', '-f', default='samples/mixed.log.gz',
                       help='Test file to evaluate')
    parser.add_argument('--output', '-o', default='evaluation_report.json',
                       help='Output report file')
    parser.add_argument('--working-dir', '-d', default='.',
                       help='Working directory (default: current directory)')

    args = parser.parse_args()

    grader = LogGrader(args.working_dir)

    # Generate test data if it doesn't exist
    if not os.path.exists(args.file):
        print(f"Test file {args.file} not found, generating...")
        cmd = [sys.executable, 'samples/generator.py', '--seed', '42', '--count', '1000',
               '--output', args.file, '--compress']
        success, stdout, stderr = grader.run_command(cmd)

        if not success:
            print(f"Failed to generate test data: {stderr}")
            sys.exit(1)

    # Run evaluation
    results = grader.generate_report(args.file)

    # Save and print results
    grader.save_report(args.output)
    grader.print_summary()

    # Exit with appropriate code
    sys.exit(0 if results.get('summary', {}).get('meets_requirements', False) else 1)

if __name__ == "__main__":
    main()