import logging
import json
import time
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import queue
import uuid
import os
from collections import defaultdict
import aiofiles
import asyncio

from .correlator import CorrelatedEvent

logger = logging.getLogger(__name__)

class ActionStatus(Enum):
    PENDING = "pending"
    EXECUTED = "executed"
    SKIPPED = "skipped"
    FAILED = "failed"

class ActionType(Enum):
    BLOCK_IP = "block_ip"
    THROTTLE_IP = "throttle_ip"
    REVOKE_TOKEN = "revoke_token"
    REDACT_LOG = "redact_log"
    NOTIFY = "notify"

@dataclass
class ActionTarget:
    ip: Optional[str] = None
    token: Optional[str] = None
    session_id: Optional[str] = None
    user: Optional[str] = None
    tenant: Optional[str] = None
    ttl_sec: Optional[int] = None

@dataclass
class Action:
    action_id: str
    action_type: ActionType
    target: ActionTarget
    status: ActionStatus
    correlation_id: str
    reason: str
    idempotent_key: str
    created_at: datetime
    executed_at: Optional[datetime] = None
    execution_result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None

class ActionBus:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.action_timeout = config.get('responder', {}).get('action_timeout', 5)
        self.max_actions_per_second = config.get('responder', {}).get('max_actions_per_second', 100)

        # Action storage and tracking
        self.action_history = []
        self.idempotency_cache = {}
        self.action_stats = defaultdict(int)

        # Rate limiting
        self.action_timestamps = deque(maxlen=self.max_actions_per_second)

        # Action registry
        self.action_handlers = {
            ActionType.BLOCK_IP: self.handle_block_ip,
            ActionType.THROTTLE_IP: self.handle_throttle_ip,
            ActionType.REVOKE_TOKEN: self.handle_revoke_token,
            ActionType.REDACT_LOG: self.handle_redact_log,
            ActionType.NOTIFY: self.handle_notify
        }

        # Output files
        self.signals_file = config.get('output', {}).get('signals_file', 'out/signals.jsonl')
        self.actions_file = config.get('output', {}).get('actions_file', 'out/actions.jsonl')
        self.metrics_file = config.get('output', {}).get('metrics_file', 'out/metrics.json')

        # Ensure output directory exists
        os.makedirs(os.path.dirname(self.signals_file), exist_ok=True)
        os.makedirs(os.path.dirname(self.actions_file), exist_ok=True)
        os.makedirs(os.path.dirname(self.metrics_file), exist_ok=True)

    def generate_idempotent_key(self, action_type: ActionType, target: ActionTarget) -> str:
        """Generate idempotent key for action"""
        key_parts = [action_type.value]

        if target.ip:
            key_parts.append(f"ip:{target.ip}")
        if target.token:
            key_parts.append(f"token:{target.token}")
        if target.session_id:
            key_parts.append(f"session:{target.session_id}")
        if target.user:
            key_parts.append(f"user:{target.user}")
        if target.tenant:
            key_parts.append(f"tenant:{target.tenant}")

        return "|".join(key_parts)

    def check_rate_limit(self) -> bool:
        """Check if rate limit is exceeded"""
        current_time = time.time()

        # Remove timestamps older than 1 second
        while self.action_timestamps and current_time - self.action_timestamps[0] > 1.0:
            self.action_timestamps.popleft()

        # Check if we're at the limit
        if len(self.action_timestamps) >= self.max_actions_per_second:
            return False

        self.action_timestamps.append(current_time)
        return True

    def is_duplicate_action(self, idempotent_key: str) -> bool:
        """Check if action is duplicate using idempotent key"""
        current_time = datetime.now()

        # Clean up old entries
        expired_keys = [
            key for key, timestamp in self.idempotency_cache.items()
            if (current_time - timestamp).total_seconds() > 300  # 5 minutes
        ]
        for key in expired_keys:
            del self.idempotency_cache[key]

        return idempotent_key in self.idempotency_cache

    def create_action(self, action_type: ActionType, target: ActionTarget,
                     correlation_id: str, reason: str) -> Optional[Action]:
        """Create new action with validation"""
        try:
            # Generate idempotent key
            idempotent_key = self.generate_idempotent_key(action_type, target)

            # Check for duplicates
            if self.is_duplicate_action(idempotent_key):
                logger.info(f"Duplicate action skipped: {idempotent_key}")
                self.action_stats['duplicate_actions'] += 1
                return None

            # Check rate limit
            if not self.check_rate_limit():
                logger.warning("Rate limit exceeded for actions")
                self.action_stats['rate_limited_actions'] += 1
                return None

            # Create action
            action = Action(
                action_id=str(uuid.uuid4()),
                action_type=action_type,
                target=target,
                status=ActionStatus.PENDING,
                correlation_id=correlation_id,
                reason=reason,
                idempotent_key=idempotent_key,
                created_at=datetime.now()
            )

            # Register in idempotency cache
            self.idempotency_cache[idempotent_key] = datetime.now()

            return action

        except Exception as e:
            logger.error(f"Failed to create action: {e}")
            return None

    async def execute_action(self, action: Action) -> Action:
        """Execute action asynchronously"""
        try:
            handler = self.action_handlers.get(action.action_type)
            if not handler:
                action.status = ActionStatus.FAILED
                action.error_message = f"No handler for action type: {action.action_type}"
                return action

            # Execute action with timeout
            try:
                result = await asyncio.wait_for(
                    handler(action.target),
                    timeout=self.action_timeout
                )

                action.status = ActionStatus.EXECUTED
                action.executed_at = datetime.now()
                action.execution_result = result

                logger.info(f"Action executed successfully: {action.action_id}")

            except asyncio.TimeoutError:
                action.status = ActionStatus.FAILED
                action.error_message = "Action execution timeout"
                logger.warning(f"Action timeout: {action.action_id}")

            except Exception as e:
                action.status = ActionStatus.FAILED
                action.error_message = str(e)
                logger.error(f"Action execution failed: {action.action_id} - {e}")

        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error_message = f"Action processing error: {e}"
            logger.error(f"Action processing failed: {action.action_id} - {e}")

        # Update stats
        self.action_stats[f"actions_{action.status.value}"] += 1

        return action

    async def handle_block_ip(self, target: ActionTarget) -> Dict[str, Any]:
        """Handle IP blocking action"""
        if not target.ip:
            raise ValueError("IP address required for block_ip action")

        # Simulate IP blocking - in real implementation would integrate with firewall/WAF
        block_result = {
            'ip': target.ip,
            'action': 'blocked',
            'ttl_sec': target.ttl_sec or 3600,
            'timestamp': datetime.now().isoformat(),
            'simulated': True
        }

        # Log the blocking action
        logger.info(f"IP blocked: {target.ip} for {target.ttl_sec or 3600}s")

        # Simulate API call to external system
        await asyncio.sleep(0.1)  # Simulate network latency

        return block_result

    async def handle_throttle_ip(self, target: ActionTarget) -> Dict[str, Any]:
        """Handle IP throttling action"""
        if not target.ip:
            raise ValueError("IP address required for throttle_ip action")

        throttle_result = {
            'ip': target.ip,
            'action': 'throttled',
            'rate_limit': '100 requests per minute',
            'ttl_sec': target.ttl_sec or 1800,
            'timestamp': datetime.now().isoformat(),
            'simulated': True
        }

        logger.info(f"IP throttled: {target.ip} for {target.ttl_sec or 1800}s")

        await asyncio.sleep(0.05)  # Simulate network latency

        return throttle_result

    async def handle_revoke_token(self, target: ActionTarget) -> Dict[str, Any]:
        """Handle token revocation action"""
        if not target.token and not target.session_id:
            raise ValueError("Token or session ID required for revoke_token action")

        revoke_result = {
            'token': target.token,
            'session_id': target.session_id,
            'user': target.user,
            'action': 'revoked',
            'timestamp': datetime.now().isoformat(),
            'simulated': True
        }

        logger.info(f"Token revoked for user: {target.user or 'unknown'}")

        await asyncio.sleep(0.1)  # Simulate network latency

        return revoke_result

    async def handle_redact_log(self, target: ActionTarget) -> Dict[str, Any]:
        """Handle log redaction action"""
        redact_result = {
            'tenant': target.tenant,
            'action': 'redact_enabled',
            'timestamp': datetime.now().isoformat(),
            'simulated': True
        }

        logger.info(f"Log redaction enabled for tenant: {target.tenant or 'default'}")

        await asyncio.sleep(0.02)  # Simulate processing time

        return redact_result

    async def handle_notify(self, target: ActionTarget) -> Dict[str, Any]:
        """Handle notification action"""
        notify_result = {
            'tenant': target.tenant,
            'user': target.user,
            'action': 'notification_sent',
            'timestamp': datetime.now().isoformat(),
            'simulated': True
        }

        logger.info(f"Notification sent to tenant: {target.tenant or 'default'}")

        await asyncio.sleep(0.1)  # Simulate notification latency

        return notify_result

    def determine_actions(self, event: Dict[str, Any], correlated_event: CorrelatedEvent) -> List[Action]:
        """Determine appropriate actions based on event"""
        actions = []

        # Action determination logic based on severity and threat types
        severity = correlated_event.severity
        threat_types = correlated_event.threat_types
        source_ip = event.get('source_ip')
        tenant = event.get('tenant')
        user = event.get('user')

        # Critical severity actions
        if severity == 'critical':
            if source_ip:
                # Block IP for critical threats
                actions.append(self.create_action(
                    ActionType.BLOCK_IP,
                    ActionTarget(ip=source_ip, ttl_sec=3600),
                    correlated_event.correlation_id,
                    f"Critical severity threat: {', '.join(threat_types)}"
                ))

            # Redact logs for tenant
            actions.append(self.create_action(
                ActionType.REDACT_LOG,
                ActionTarget(tenant=tenant),
                correlated_event.correlation_id,
                f"Critical threat detected for tenant {tenant}"
            ))

        # High severity actions
        elif severity == 'high':
            if source_ip:
                # Throttle IP for high severity threats
                actions.append(self.create_action(
                    ActionType.THROTTLE_IP,
                    ActionTarget(ip=source_ip, ttl_sec=1800),
                    correlated_event.correlation_id,
                    f"High severity threat: {', '.join(threat_types)}"
                ))

        # SQLi specific actions
        if 'sqli' in threat_types:
            if user:
                actions.append(self.create_action(
                    ActionType.REVOKE_TOKEN,
                    ActionTarget(user=user, tenant=tenant),
                    correlated_event.correlation_id,
                    "SQL injection attempt detected"
                ))

        # XSS specific actions
        if 'xss' in threat_types:
            actions.append(self.create_action(
                ActionType.NOTIFY,
                ActionTarget(tenant=tenant, user=user),
                correlated_event.correlation_id,
                "XSS attempt detected"
            ))

        # Multiple threat types in window
        if correlated_event.window_hits > 3 and len(threat_types) > 1:
            if source_ip:
                actions.append(self.create_action(
                    ActionType.BLOCK_IP,
                    ActionTarget(ip=source_ip, ttl_sec=7200),
                    correlated_event.correlation_id,
                    f"Multiple threat types detected: {', '.join(threat_types)}"
                ))

        # Filter out None actions (duplicates, rate limited)
        return [action for action in actions if action is not None]

    async def process_correlated_event(self, event: Dict[str, Any], correlated_event: CorrelatedEvent) -> List[Action]:
        """Process correlated event and execute actions"""
        try:
            # Determine required actions
            actions = self.determine_actions(event, correlated_event)

            if not actions:
                logger.debug(f"No actions required for event {correlated_event.event_id}")
                return []

            # Execute actions concurrently
            action_tasks = [self.execute_action(action) for action in actions]
            executed_actions = await asyncio.gather(*action_tasks, return_exceptions=True)

            # Filter out exceptions and keep successful actions
            final_actions = []
            for i, result in enumerate(executed_actions):
                if isinstance(result, Exception):
                    logger.error(f"Action execution error: {result}")
                else:
                    final_actions.append(result)

            # Store actions in history
            self.action_history.extend(final_actions)

            # Write to output file
            await self.write_actions_to_file(final_actions)

            return final_actions

        except Exception as e:
            logger.error(f"Failed to process correlated event: {e}")
            return []

    async def write_actions_to_file(self, actions: List[Action]):
        """Write actions to JSONL file"""
        try:
            async with aiofiles.open(self.actions_file, mode='a', encoding='utf-8') as f:
                for action in actions:
                    action_dict = {
                        'action_id': action.action_id,
                        'ts': action.executed_at.isoformat() if action.executed_at else action.created_at.isoformat(),
                        'correlation_id': action.correlation_id,
                        'kind': action.action_type.value,
                        'target': {
                            'ip': action.target.ip,
                            'ttl_sec': action.target.ttl_sec
                        },
                        'status': action.status.value,
                        'reason': action.reason,
                        'idempotent_key': action.idempotent_key
                    }

                    await f.write(json.dumps(action_dict, ensure_ascii=False) + '\n')

        except Exception as e:
            logger.error(f"Failed to write actions to file: {e}")

    async def write_signal_to_file(self, event: Dict[str, Any], correlated_event: CorrelatedEvent):
        """Write signal to JSONL file"""
        try:
            signal = {
                'event_id': correlated_event.event_id,
                'ts': correlated_event.timestamp.isoformat(),
                'tenant': correlated_event.tenant or 'default',
                'src_ip': correlated_event.source_ip,
                'severity': correlated_event.severity,
                'threat_types': correlated_event.threat_types,
                'reason': correlated_event.reason,
                'matched_rules': correlated_event.matched_rules,
                'ml_score': correlated_event.ml_score,
                'window': f"{self.config.get('correlator', {}).get('window_seconds', 60)}s",
                'correlation_id': correlated_event.correlation_id,
                'masked_fields': [],
                'sanitized_excerpt': event.get('message', '')[:200] + '...' if len(event.get('message', '')) > 200 else event.get('message', ''),
                'action_planned': [action.action_type.value for action in self.determine_actions(event, correlated_event)]
            }

            async with aiofiles.open(self.signals_file, mode='a', encoding='utf-8') as f:
                await f.write(json.dumps(signal, ensure_ascii=False) + '\n')

        except Exception as e:
            logger.error(f"Failed to write signal to file: {e}")

    def get_action_stats(self) -> Dict[str, Any]:
        """Get action execution statistics"""
        stats = dict(self.action_stats)
        stats['total_actions'] = len(self.action_history)
        stats['idempotency_cache_size'] = len(self.idempotency_cache)

        # Calculate success rate
        executed_count = stats.get('actions_executed', 0)
        failed_count = stats.get('actions_failed', 0)
        total_attempted = executed_count + failed_count

        if total_attempted > 0:
            stats['success_rate'] = executed_count / total_attempted
        else:
            stats['success_rate'] = 1.0

        return stats

    def get_recent_actions(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent action history"""
        recent_actions = self.action_history[-limit:]
        return [asdict(action) for action in recent_actions]