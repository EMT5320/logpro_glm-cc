"""
Log Risk Detection and Auto-Remediation System
"""

__version__ = "1.0.0"
__author__ = "Security Team"

from .parser import LogParser
from .normalizer import LogNormalizer
from .detector import ThreatDetector
from .correlator import EventCorrelator
from .responder import ActionBus
from .config import ConfigManager

__all__ = [
    'LogParser',
    'LogNormalizer',
    'ThreatDetector',
    'EventCorrelator',
    'ActionBus',
    'ConfigManager'
]