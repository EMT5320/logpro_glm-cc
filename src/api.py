import asyncio
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn

from .main import LogAnalyzer
from .config import ConfigManager

logger = logging.getLogger(__name__)

# Pydantic models for API
class HealthResponse(BaseModel):
    status: str
    timestamp: str
    version: str

class AnalyzeTextRequest(BaseModel):
    text: str
    tenant: Optional[str] = None

class AnalyzeTextResponse(BaseModel):
    event_id: str
    threat_types: List[str]
    severity: str
    confidence: float
    reason: str
    actions: List[str]

class TrainRequest(BaseModel):
    texts: List[str]
    labels: List[int]
    tenant: Optional[str] = None

class TrainResponse(BaseModel):
    status: str
    samples: int
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1: Optional[float] = None
    message: Optional[str] = None

class ActionInfo(BaseModel):
    action_id: str
    action_type: str
    status: str
    correlation_id: str
    reason: str
    created_at: str

class MetricsResponse(BaseModel):
    throughput_lps: float
    duration_seconds: float
    total_lines: int
    threat_events: int
    actions_taken: int
    rule_hits: int
    correlation_stats: Dict[str, Any]
    action_stats: Dict[str, Any]

class LogAnalyzerAPI:
    def __init__(self, config_path: str = "config.yml"):
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.load_config()
        self.analyzer = LogAnalyzer(config_path)
        self.app = FastAPI(
            title="Log Risk Detection API",
            description="API for log risk detection and auto-remediation",
            version="1.0.0"
        )
        self.setup_routes()

    def setup_routes(self):
        """Setup API routes"""

        @self.app.get("/health", response_model=HealthResponse)
        async def health_check():
            """Health check endpoint"""
            return HealthResponse(
                status="healthy",
                timestamp=datetime.now().isoformat(),
                version="1.0.0"
            )

        @self.app.post("/analyze/text", response_model=AnalyzeTextResponse)
        async def analyze_text(request: AnalyzeTextRequest):
            """Analyze a single text entry"""
            try:
                # Create a mock event from text
                raw_event = {
                    'message': request.text,
                    'tenant': request.tenant or 'default',
                    'timestamp': datetime.now().isoformat(),
                    'event_id': f"api_{datetime.now().timestamp()}"
                }

                # Process the event
                result = await self.analyzer.process_event(raw_event)

                if not result:
                    return AnalyzeTextResponse(
                        event_id=raw_event['event_id'],
                        threat_types=[],
                        severity="low",
                        confidence=0.0,
                        reason="No threats detected",
                        actions=[]
                    )

                detection_result = result['detection_result']
                actions = [action.action_type.value for action in result['actions']]

                return AnalyzeTextResponse(
                    event_id=detection_result.event_id,
                    threat_types=detection_result.threat_types,
                    severity=detection_result.severity,
                    confidence=detection_result.confidence,
                    reason=detection_result.reason,
                    actions=actions
                )

            except Exception as e:
                logger.error(f"Error in analyze_text: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.post("/analyze/file")
        async def analyze_file(
            file: UploadFile = File(...),
            tenant: Optional[str] = None,
            background_tasks: BackgroundTasks = None
        ):
            """Analyze uploaded log file"""
            try:
                # Save uploaded file temporarily
                temp_file_path = f"temp_{file.filename}"
                with open(temp_file_path, "wb") as buffer:
                    content = await file.read()
                    buffer.write(content)

                # Process file in background
                if background_tasks:
                    background_tasks.add_task(self.process_file_background, temp_file_path, tenant)
                    return {"status": "processing", "message": "File analysis started"}
                else:
                    # Process synchronously
                    metrics = await self.analyzer.process_file(temp_file_path, tenant)
                    os.remove(temp_file_path)
                    return {"status": "completed", "metrics": metrics}

            except Exception as e:
                logger.error(f"Error in analyze_file: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.post("/train", response_model=TrainResponse)
        async def train_model(request: TrainRequest):
            """Train ML model"""
            try:
                if len(request.texts) != len(request.labels):
                    raise HTTPException(
                        status_code=400,
                        detail="Number of texts and labels must match"
                    )

                result = self.analyzer.detector.train_ml_model(request.texts, request.labels)

                if result['status'] == 'success':
                    return TrainResponse(
                        status="success",
                        samples=result['samples'],
                        accuracy=result['accuracy'],
                        precision=result['precision'],
                        recall=result['recall'],
                        f1=result['f1']
                    )
                else:
                    return TrainResponse(
                        status="error",
                        samples=len(request.texts),
                        message=result['message']
                    )

            except Exception as e:
                logger.error(f"Error in train_model: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.post("/rules/reload")
        async def reload_rules():
            """Reload detection rules"""
            try:
                # Reload configuration
                self.config_manager.reload_config()

                # Reinitialize detector with new config
                self.analyzer.detector = ThreatDetector(self.config)

                return {"status": "success", "message": "Rules reloaded successfully"}

            except Exception as e:
                logger.error(f"Error reloading rules: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/metrics", response_model=MetricsResponse)
        async def get_metrics():
            """Get system metrics"""
            try:
                metrics = self.analyzer.get_final_metrics()
                return MetricsResponse(**metrics)

            except Exception as e:
                logger.error(f"Error getting metrics: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/actions", response_model=List[ActionInfo])
        async def get_actions(limit: int = 100):
            """Get recent actions"""
            try:
                actions = self.analyzer.responder.get_recent_actions(limit)
                return [
                    ActionInfo(
                        action_id=action['action_id'],
                        action_type=action['action_type'],
                        status=action['status'],
                        correlation_id=action['correlation_id'],
                        reason=action['reason'],
                        created_at=action['created_at']
                    )
                    for action in actions
                ]

            except Exception as e:
                logger.error(f"Error getting actions: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/config")
        async def get_config():
            """Get current configuration"""
            try:
                # Return config without sensitive data
                safe_config = {
                    'system': self.config.get('system', {}),
                    'detector': {
                        'enable_ml': self.config.get('detector', {}).get('enable_ml', True),
                        'ml_threshold': self.config.get('detector', {}).get('ml_threshold', 0.8)
                    },
                    'correlator': {
                        'window_seconds': self.config.get('correlator', {}).get('window_seconds', 60)
                    },
                    'rules': {k: len(v) for k, v in self.config.get('rules', {}).items()}
                }
                return safe_config

            except Exception as e:
                logger.error(f"Error getting config: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.exception_handler(Exception)
        async def global_exception_handler(request, exc):
            """Global exception handler"""
            logger.error(f"Unhandled exception: {exc}")
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error"}
            )

    async def process_file_background(self, file_path: str, tenant: Optional[str]):
        """Process file in background"""
        try:
            metrics = await self.analyzer.process_file(file_path, tenant)
            logger.info(f"Background processing completed: {metrics}")
        except Exception as e:
            logger.error(f"Background processing failed: {e}")
        finally:
            # Clean up temporary file
            if os.path.exists(file_path):
                os.remove(file_path)

    def run(self, host: str = "0.0.0.0", port: int = 8000):
        """Run the API server"""
        uvicorn.run(
            self.app,
            host=host,
            port=port,
            log_level="info"
        )

def create_app(config_path: str = "config.yml") -> FastAPI:
    """Create FastAPI application"""
    api = LogAnalyzerAPI(config_path)
    return api.app

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Log Analyzer API Server")
    parser.add_argument("--config", "-c", default="config.yml", help="Configuration file")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")

    args = parser.parse_args()

    api = LogAnalyzerAPI(args.config)
    api.run(host=args.host, port=args.port)