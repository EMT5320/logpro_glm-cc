# System Architecture

## Overview

The Log Risk Detection and Auto-Remediation System is designed as a modular, scalable architecture that processes log data through multiple stages of analysis and response. The system supports real-time processing of multi-source logs with advanced threat detection capabilities.

## Architecture Diagram

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Log Sources   │    │   Input Layer   │    │  Processing     │
│                 │    │                 │    │  Pipeline       │
│ • Web Servers   │───▶│ • File Input    │───▶│ • Parser        │
│ • Applications  │    │ • Stream Input  │    │ • Normalizer    │
│ • Databases     │    │ • API Input     │    │ • Detector      │
│ • Containers    │    │                 │    │ • Correlator    │
│ • Cloud Audit   │    │                 │    │ • Responder     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                          │
                                                          ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Output Layer  │    │   Management    │    │   Monitoring    │
│                 │    │                 │    │                 │
│ • signals.jsonl │    │ • Configuration │    │ • Metrics       │
│ • actions.jsonl │    │ • Rules         │    │ • Health Checks │
│ • metrics.json  │    │ • ML Models     │    │ • Performance   │
│ • API Responses │    │ • Tenants       │    │ • Alerts        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Core Components

### 1. Parser Component (`src/parser.py`)

**Purpose**: Multi-format log parsing with robustness features

**Key Responsibilities**:
- Automatic format detection (Nginx, Apache, JSON, Cloud Audit, Container, Database)
- Handling of encoding issues (UTF-8, GBK, ASCII with BOM)
- Support for compressed files (.gz)
- Line length validation and truncation handling
- Anti-evasion preprocessing (multi-round decoding)

**Data Flow**:
```
Raw Log → Format Detection → Encoding Handling → Deobfuscation → Parsed Event
```

**Key Classes**:
- `LogParser`: Main parsing orchestrator
- Format-specific parsers for different log types

**Robustness Features**:
- Mixed encoding support (UTF-8/GBK fallback)
- BOM header handling
- Line length limits (configurable, default 1MB)
- Empty line skipping
- Malformed line recovery

### 2. Normalizer Component (`src/normalizer.py`)

**Purpose**: Standardize events into unified structure with PII masking

**Key Responsibilities**:
- Event field normalization and mapping
- Timestamp standardization (ISO8601 UTC)
- IP address normalization and validation
- PII detection and masking (email, phone, ID card, credit card, API keys)
- User-Agent parsing and geolocation simulation
- Severity level normalization

**Data Flow**:
```
Parsed Event → Field Mapping → Timestamp Normalization → PII Masking → Standardized Event
```

**Key Classes**:
- `LogNormalizer`: Main normalization engine

**PII Protection**:
- Email masking: `user@domain.com` → `u***@d****.com`
- Phone masking: `13812345678` → `138****5678`
- ID card masking: `110101199001011234` → `110101******1234`
- Credit card masking: `4111111111111111` → `************1111`
- API key masking: `abcdef123456` → `********`

### 3. Detector Component (`src/detector.py`)

**Purpose**: Multi-layered threat detection combining rules, ML, and anomaly detection

**Key Responsibilities**:
- Rule-based pattern matching for known attack types
- Machine learning classification for unknown threats
- Behavioral anomaly detection
- Confidence scoring and severity determination
- Anti-evasion countermeasures

**Architecture**:
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Rule Engine    │    │   ML Detector   │    │ Anomaly Detector│
│                 │    │                 │    │                 │
│ • SQLi Patterns │    │ • TF-IDF        │    │ • Session       │
│ • XSS Patterns  │    │ • Logistic Reg   │    │ • Baseline      │
│ • Cmd Injection │    │ • Feature Ext   │    │ • Isolation     │
│ • Path Traversal│    │ • Online Learning│    │ • Forest        │
│ • SSRF/Log4Shell│    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

**Key Classes**:
- `RuleEngine`: Pattern matching and rule management
- `MachineLearningDetector`: ML model training and inference
- `AnomalyDetector`: Behavioral baseline and anomaly scoring
- `ThreatDetector`: Main detection orchestrator

**Detection Strategies**:

1. **Rule-Based Detection**:
   - Predefined patterns for common attack types
   - Configurable severity levels
   - Support for regex variations and obfuscation

2. **Machine Learning Detection**:
   - TF-IDF vectorization for text features
   - Logistic regression classification
   - Online/incremental learning support
   - Confidence threshold tuning

3. **Anomaly Detection**:
   - Session-based behavioral analysis
   - Isolation Forest for outlier detection
   - Baseline establishment and drift detection
   - Multi-feature correlation

### 4. Correlator Component (`src/correlator.py`)

**Purpose**: Event correlation, deduplication, and suppression

**Key Responsibilities**:
- Multi-dimensional event correlation (IP, tenant, session, user, UA)
- Sliding window analysis (configurable, default 60s)
- Duplicate detection and suppression
- Pattern recognition and severity escalation
- TTL-based expiration

**Data Structures**:
```python
event_windows = defaultdict(deque)        # Sliding window storage
dedup_cache = {}                         # Fingerprint → timestamp
suppression_list = {}                    # target → expiry_time
correlation_stats = defaultdict(int)      # Statistics tracking
```

**Key Classes**:
- `EventCorrelator`: Main correlation engine
- `CorrelatedEvent`: Correlated event data structure

**Correlation Dimensions**:
- **IP-based**: Events from same source IP
- **Tenant-based**: Events within same tenant
- **Session-based**: Events with same session identifier
- **User-based**: Events from same user account
- **User-Agent**: Events with similar browser fingerprints

### 5. Responder Component (`src/responder.py`)

**Purpose**: Automated action execution with audit trail

**Key Responsibilities**:
- Action determination based on threat severity and type
- Idempotent action execution
- Rate limiting and timeout handling
- Action audit logging
- Action bus for extensible response types

**Action Types**:
- `block_ip`: Block source IP (TTL-based)
- `throttle_ip`: Rate limit source IP
- `revoke_token`: Revoke user session/token
- `redact_log`: Enable log redaction for tenant
- `notify`: Send security notifications

**Key Classes**:
- `ActionBus`: Action execution engine
- `Action`: Action data structure
- Various action handlers

**Safety Features**:
- Idempotent key generation
- Duplicate action prevention
- Execution timeout handling
- Rate limiting protection
- Comprehensive error handling

### 6. Configuration Management (`src/config.py`)

**Purpose**: Centralized configuration with hot reload capabilities

**Key Responsibilities**:
- YAML/JSON configuration loading
- Configuration validation
- Hot reload support
- Tenant-specific configuration merging
- Default value management

**Key Classes**:
- `ConfigManager`: Configuration management engine

### 7. API Layer (`src/api.py`)

**Purpose**: RESTful HTTP API for system integration

**Key Endpoints**:
- `GET /health`: Health check
- `POST /analyze/text`: Single text analysis
- `POST /analyze/file`: File upload analysis
- `POST /train`: ML model training
- `POST /rules/reload`: Rule reload
- `GET /metrics`: System metrics
- `GET /actions`: Recent actions
- `GET /config`: Current configuration

**Key Classes**:
- `LogAnalyzerAPI`: FastAPI application wrapper

### 8. CLI Interface (`src/main.py`)

**Purpose**: Command-line interface for batch processing and system management

**Key Commands**:
- `analyze`: File/stream analysis
- `train`: ML model training
- Various options for tenant filtering, mode selection, etc.

**Key Classes**:
- `LogAnalyzer`: Main CLI application class

## Data Flow Architecture

### Processing Pipeline

```
Raw Input → Parse → Normalize → Detect → Correlate → Respond → Output
    ↓        ↓         ↓         ↓          ↓         ↓        ↓
Multi-   Standard-  Threat-   Correlated  Action    JSONL
Format   ized      Events    & Unique    Execution  Output
Logs     Events    Detected   Events     Results    Files
```

### Event Lifecycle

1. **Ingestion**: Raw log entry from file, stream, or API
2. **Parsing**: Format detection and field extraction
3. **Normalization**: Standard structure with PII masking
4. **Detection**: Multi-layered threat analysis
5. **Correlation**: Window-based event correlation
6. **Response**: Automated action execution
7. **Output**: Structured results and metrics

### State Management

**In-Memory State**:
- Event correlation windows
- Deduplication cache
- Suppression lists
- ML model instances
- Configuration cache

**Persistent State**:
- Output JSONL files
- Trained ML models
- Configuration files
- Log files

## Performance Architecture

### Concurrency Model

- **Async I/O**: Non-blocking file operations and API calls
- **Thread Pool**: Configurable worker threads for CPU-intensive tasks
- **Coroutine-based**: Async/await pattern for I/O-bound operations
- **Lock-free Data Structures**: Minimize contention in high-throughput scenarios

### Memory Management

- **Sliding Windows**: Automatic expiration of old events
- **TTL-based Cache**: Automatic cleanup of deduplication data
- **Stream Processing**: Memory-efficient file processing
- **Configurable Limits**: Prevent memory exhaustion

### Scalability Considerations

**Horizontal Scaling**:
- Stateless components (except correlation windows)
- Load balancer support
- Multiple API instances

**Vertical Scaling**:
- Configurable worker threads
- Memory limit tuning
- Batch size optimization

## Security Architecture

### Data Protection

- **PII Masking**: Automatic sensitive data redaction
- **Secure Storage**: No plaintext secrets
- **Audit Trail**: Complete action logging
- **Tenant Isolation**: Multi-tenant data separation

### Anti-Evasion

- **Multi-round Decoding**: URL/Base64/Hex encoding layers
- **Pattern Variations**: Case-insensitive, fragmented patterns
- **Normalization**: Whitespace and comment handling
- **Feature Extraction**: Robust feature engineering for ML

### Access Control

- **Configuration Protection**: Secure configuration management
- **API Authentication**: Optional API key support
- **File Permissions**: Secure file access controls
- **Process Isolation**: Separate processes for different components

## Error Handling and Resilience

### Fault Tolerance

- **Graceful Degradation**: Continue processing despite component failures
- **Circuit Breakers**: Prevent cascading failures
- **Retry Logic**: Configurable retry for transient failures
- **Fallback Mechanisms**: Alternative processing paths

### Error Recovery

- **Automatic Cleanup**: Resource management and cleanup
- **State Recovery**: Restore from persistent state
- **Error Logging**: Comprehensive error tracking
- **Health Checks**: Component health monitoring

### Monitoring and Observability

**Metrics**:
- Processing throughput (lines/second)
- Detection accuracy (precision/recall/F1)
- Action execution success rates
- Memory usage and latency
- Error rates and types

**Logging**:
- Structured logging with correlation IDs
- Configurable log levels
- Performance timing data
- Security event logging

**Health Monitoring**:
- Component health checks
- Resource utilization monitoring
- Configuration validation
- Dependency health checking

## Integration Architecture

### Input Integration

- **File System**: Watched directories and scheduled processing
- **Stream Processing**: Stdin and named pipe support
- **API Integration**: RESTful endpoints for real-time analysis
- **Message Queues**: Extensible for future Kafka/RabbitMQ support

### Output Integration

- **Structured Output**: JSONL format for easy parsing
- **SIEM Integration**: Standardized event format
- **Database Output**: Configurable database storage
- **Notification Systems**: Email and webhook support

### External System Integration

- **WAF/Firewall**: IP blocking integration points
- **Identity Systems**: Token revocation capabilities
- **Logging Platforms**: Forwarding to centralized logging
- **Monitoring Systems**: Metrics and alerting integration

This architecture provides a robust, scalable foundation for real-time log analysis and threat detection with comprehensive automation capabilities.