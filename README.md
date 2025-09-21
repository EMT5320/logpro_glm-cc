# Log Risk Detection and Auto-Remediation System

A comprehensive real-time log risk detection and auto-remediation system that supports multi-source log ingestion, advanced threat detection, and automated response actions.

## Features

### Multi-Source Log Parsing
- **Web Server Logs**: Nginx/Apache access logs with mixed/missing fields and timezone handling
- **Application Logs**: JSON logs with nested structures, arrays, and multi-line stack traces
- **Database Logs**: Audit logs for SELECT/INSERT/DDL operations and exception handling
- **Container Logs**: Kubernetes runtime logs with pod/container identification
- **Cloud Audit Logs**: Semi-structured user/role/resource/action/result logs
- **Robust Processing**: Handles empty lines, truncation, BOM, mixed encodings (UTF-8/GBK), and lines ≥1MB

### Advanced Threat Detection
- **Rule-Based Detection**: Configurable patterns for SQLi, XSS, command injection, path traversal, SSRF, Log4Shell
- **Machine Learning**: TF-IDF + Logistic Regression with online/incremental learning capabilities
- **Anomaly Detection**: Isolation Forest for behavioral anomaly detection in session windows
- **Anti-Evasion**: Multi-round decoding, normalization, and comment stripping to counter obfuscation

### Event Correlation
- **Sliding Window**: 60-second configurable correlation windows
- **Multi-Dimensional**: IP, tenant, session, user, and User-Agent based correlation
- **Deduplication**: Fingerprint-based duplicate detection with TTL
- **Suppression**: Configurable suppression lists to prevent alert storms

### Automated Response
- **Action Bus**: block_ip, throttle_ip, revoke_token, redact_log, notify actions
- **Idempotent Operations**: Ensures safe repeated execution
- **Rate Limiting**: Configurable action execution limits
- **Audit Trail**: Complete action logging and status tracking

### System Interfaces
- **CLI Tool**: Full command-line interface with file/stream processing
- **REST API**: FastAPI-based HTTP API for integration
- **Configuration Hot Reload**: Runtime rule and configuration updates
- **Comprehensive Output**: Structured JSONL outputs for signals, actions, and metrics

## Quick Start

### Prerequisites
- Python 3.8+
- pip package manager

### Installation

1. **Clone or download the project**
```bash
cd glm-cc
```

2. **Run the setup script (Windows)**
```batch
run.bat
```

Or manually install dependencies:
```bash
pip install -r requirements.txt
```

### Basic Usage

#### Command Line Interface

**Analyze a log file:**
```bash
python src/main.py analyze --file samples/mixed.log.gz --tenant acme
```

**Stream processing from stdin:**
```bash
cat samples/mixed.log | python src/main.py analyze --stdin
```

**Train ML model:**
```bash
python src/main.py train
```

**Different processing modes:**
```bash
python src/main.py analyze --file test.log --mode fast      # Minimal ML, quick processing
python src/main.py analyze --file test.log --mode balanced  # Balanced accuracy/speed
python src/main.py analyze --file test.log --mode accurate # Full ML, thorough analysis
```

#### REST API

**Start the API server:**
```bash
python src/api.py --host 0.0.0.0 --port 8000
```

**API Endpoints:**
```bash
# Health check
curl http://localhost:8000/health

# Analyze text
curl -X POST http://localhost:8000/analyze/text \
  -H "Content-Type: application/json" \
  -d '{"text": "SELECT * FROM users WHERE id = 1 OR 1=1"}'

# Upload and analyze file
curl -X POST http://localhost:8000/analyze/file \
  -F "file=@test.log"

# Train model
curl -X POST http://localhost:8000/train \
  -H "Content-Type: application/json" \
  -d '{"texts": ["SELECT * FROM users", "malicious payload"], "labels": [0, 1]}'

# Get metrics
curl http://localhost:8000/metrics

# Reload rules
curl -X POST http://localhost:8000/rules/reload
```

## Configuration

### Configuration File (config.yml)

The system uses YAML configuration for easy customization:

```yaml
system:
  max_line_length: 1048576  # 1MB max line size
  max_decode_rounds: 5      # Max deobfuscation rounds
  timezone: "UTC"
  concurrent_workers: 4
  rate_limit_rps: 10000

detector:
  enable_ml: true
  ml_threshold: 0.8
  anomaly_window: 3600

correlator:
  window_seconds: 60       # Correlation window
  dedup_ttl: 600          # Duplicate suppression TTL
  max_events_per_window: 100

responder:
  action_timeout: 5        # Action execution timeout
  max_actions_per_second: 100

rules:
  sqli:
    - pattern: "(?i)(union\s+select|select\s+.*\s+from\s+.*\s+where)"
      severity: "high"
    - pattern: "(?i)(drop\s+table|alter\s+table)"
      severity: "critical"
```

### Environment Variables

Key environment variables:

- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARN, ERROR)
- `CONFIG_FILE`: Path to configuration file
- `API_HOST`: API server host (default: 0.0.0.0)
- `API_PORT`: API server port (default: 8000)

## Architecture

### System Components

1. **Parser**: Multi-format log parsing with robustness features
2. **Normalizer**: Event standardization and PII masking
3. **Detector**: Rule-based + ML + anomaly detection
4. **Correlator**: Event correlation and deduplication
5. **Responder**: Action execution and audit
6. **API**: RESTful interface for integration
7. **CLI**: Command-line interface

### Data Flow

```
Raw Logs → Parser → Normalizer → Detector → Correlator → Responder → Output
    ↓           ↓           ↓          ↓           ↓         ↓
Multi-format  Standard    Threat      Events     Actions   JSONL Files
Support      Events      Detection   Correlated  Executed  (signals.jsonl
                                    & Unique              actions.jsonl
                                                         metrics.json)
```

## Testing and Evaluation

### Generate Test Data

```bash
# Generate mixed normal/attack logs
python samples/generator.py --seed 42 --count 1000 --attack-ratio 0.1 --output samples/mixed.log.gz

# Generate session-based attack scenarios
python samples/generator.py --seed 42 --session-attack --output samples/session_attacks.log
```

### Run Evaluation

```bash
# Comprehensive system evaluation
python grader.py --file samples/mixed.log.gz

# Custom evaluation with specific test file
python grader.py --file custom_test.log --output custom_report.json
```

### Performance Benchmarks

The system is designed to meet the following performance targets:

- **Throughput**: ≥5,000 lines/second in balanced mode
- **Latency**: ≤15ms average per line
- **Memory**: ≤600MB peak usage
- **Accuracy**: ≥0.85 F1 score for high/critical events
- **Detection**: Supports multiple evasion techniques

## Security Features

### Anti-Evasion Techniques

1. **Multi-Round Decoding**: URL, Base64, Hex encoding layers
2. **Normalization**: Case folding, whitespace normalization
3. **Comment Stripping**: SQL and script comment removal
4. **Pattern Variation**: Handles mixed-case, fragmented attacks

### Data Protection

1. **PII Masking**: Automatic detection and masking of sensitive data
2. **Secure Storage**: No plaintext secrets in logs or config
3. **Access Control**: Tenant-isolated processing and storage
4. **Audit Trail**: Complete action logging with correlation IDs

## Deployment

### Production Deployment

1. **Environment Setup**:
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

2. **Configuration**:
   - Modify `config.yml` for production settings
   - Set appropriate log levels and paths
   - Configure external system integrations

3. **Service Configuration**:
   - Set up as system service (systemd/Windows Service)
   - Configure log rotation
   - Set up monitoring and alerting

### Scaling Considerations

- **Horizontal Scaling**: Multiple instances with load balancer
- **Vertical Scaling**: Increase worker threads and memory limits
- **Storage**: Externalize log storage for large volumes
- **Monitoring**: Integrate with existing monitoring systems

## Integration

### SIEM Integration

The system outputs structured JSONL files that can be easily ingested by SIEM platforms:

```json
{"event_id":"uuid","ts":"2025-09-21T12:34:56Z","tenant":"acme","src_ip":"203.0.113.5","severity":"high","threat_types":["sqli"],"reason":"matched rules: R_SQLI_001","action_planned":["block_ip"]}
```

### API Integration

Programmatic access via REST API:

```python
import requests

# Analyze text
response = requests.post(
    "http://localhost:8000/analyze/text",
    json={"text": "suspicious query", "tenant": "acme"}
)

# Get metrics
metrics = requests.get("http://localhost:8000/metrics").json()
```

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all dependencies are installed
2. **Permission Issues**: Check file permissions for output directories
3. **Memory Issues**: Reduce concurrent workers or max line size
4. **Performance Issues**: Use fast mode or reduce correlation window

### Debug Mode

Enable debug logging:
```bash
export LOG_LEVEL=DEBUG
python src/main.py analyze --file test.log
```

### Log Files

- `analyzer.log`: Main application log
- `out/signals.jsonl`: Detection results
- `out/actions.jsonl`: Executed actions
- `out/metrics.json`: Performance metrics

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit pull request

## License

This project is developed for security research and educational purposes.

## Support

For issues and questions:
- Check the troubleshooting section
- Review log files for error details
- Use debug mode for detailed logging