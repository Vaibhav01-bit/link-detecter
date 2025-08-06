#!/usr/bin/env python3
"""
PhishGuard Configuration Settings
"""

import os
from datetime import timedelta

class Config:
    """Base configuration class"""
    
    # Flask Settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'phishguard-secret-key-2024'
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() in ['true', '1', 'yes']
    
    # Server Settings
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 5000))
    THREADED = True
    
    # CORS Settings
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
    
    # Model Settings
    MODEL_DIR = os.environ.get('MODEL_DIR', 'models/')
    MODEL_WEIGHTS = {
        'random_forest': 0.4,
        'gradient_boosting': 0.35,
        'xgboost': 0.25
    }
    
    # Feature Extraction Settings
    MAX_URL_LENGTH = 2048
    FEATURE_COUNT = 30
    
    # API Rate Limiting
    RATE_LIMIT_ENABLED = os.environ.get('RATE_LIMIT_ENABLED', 'False').lower() in ['true', '1', 'yes']
    RATE_LIMIT_REQUESTS = int(os.environ.get('RATE_LIMIT_REQUESTS', 100))
    RATE_LIMIT_WINDOW = int(os.environ.get('RATE_LIMIT_WINDOW', 3600))  # 1 hour
    
    # Batch Processing
    MAX_BATCH_SIZE = int(os.environ.get('MAX_BATCH_SIZE', 100))
    
    # Logging Settings
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'phishguard.log')
    
    # Cache Settings
    CACHE_ENABLED = os.environ.get('CACHE_ENABLED', 'False').lower() in ['true', '1', 'yes']
    CACHE_TTL = int(os.environ.get('CACHE_TTL', 3600))  # 1 hour
    
    # Database Settings (for production)
    DATABASE_URL = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security Settings
    WHOIS_TIMEOUT = int(os.environ.get('WHOIS_TIMEOUT', 10))  # seconds
    REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', 5))  # seconds
    
    # Monitoring Settings
    HEALTH_CHECK_ENABLED = True
    METRICS_ENABLED = os.environ.get('METRICS_ENABLED', 'True').lower() in ['true', '1', 'yes']

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    LOG_LEVEL = 'DEBUG'

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    RATE_LIMIT_ENABLED = True
    CACHE_ENABLED = True
    LOG_LEVEL = 'WARNING'

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    LOG_LEVEL = 'DEBUG'

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on environment"""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])