"""
Middleware for RazilHub Application
Handles security, logging, rate limiting, and request processing
"""

import time
import logging
import functools
from flask import request, jsonify, current_app, g, session
from datetime import datetime
import hashlib
import json

logger = logging.getLogger(__name__)

class SecurityMiddleware:
    """Security middleware for request validation and protection"""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        app.errorhandler(403)(self.handle_forbidden)
        app.errorhandler(404)(self.handle_not_found)
        app.errorhandler(500)(self.handle_internal_error)
    
    def before_request(self):
        """Process request before handling"""
        g.start_time = time.time()
        g.request_id = self.generate_request_id()
        
        # Log request
        self.log_request()
        
        # Validate request size
        max_length = current_app.config.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024)
        if request.content_length and request.content_length > max_length:
            return jsonify({'error': 'Request too large'}), 413
        
        # Check for suspicious patterns
        if self.detect_suspicious_request():
            logger.warning(f"Suspicious request detected: {request.remote_addr}")
            return jsonify({'error': 'Suspicious request detected'}), 403
    
    def after_request(self, response):
        """Process response after handling"""
        # Add security headers
        response = self.add_security_headers(response)
        
        # Log response
        self.log_response(response)
        
        return response
    
    def add_security_headers(self, response):
        """Add security headers to response"""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Add CSP header
        csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'"
        response.headers['Content-Security-Policy'] = csp
        
        return response
    
    def generate_request_id(self):
        """Generate unique request ID"""
        timestamp = str(int(time.time() * 1000))
        random_str = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        return f"{timestamp}_{random_str}"
    
    def log_request(self):
        """Log incoming request"""
        log_data = {
            'request_id': g.request_id,
            'method': request.method,
            'path': request.path,
            'remote_addr': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if request.is_json:
            log_data['content_type'] = 'application/json'
        elif request.form:
            log_data['content_type'] = 'application/x-www-form-urlencoded'
        
        logger.info(f"Request: {json.dumps(log_data)}")
    
    def log_response(self, response):
        """Log response details"""
        duration = time.time() - g.start_time
        
        log_data = {
            'request_id': g.request_id,
            'status_code': response.status_code,
            'duration_ms': round(duration * 1000, 2),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        logger.info(f"Response: {json.dumps(log_data)}")
    
    def detect_suspicious_request(self):
        """Detect potentially malicious requests"""
        suspicious_patterns = [
            'script', 'javascript:', 'vbscript:', 'onload=',
            '../', '..\\', '/etc/passwd', '/proc/',
            'union select', 'drop table', 'delete from'
        ]
        
        # Check URL path
        path = request.path.lower()
        for pattern in suspicious_patterns:
            if pattern in path:
                return True
        
        # Check query parameters
        for value in request.args.values():
            if any(pattern in str(value).lower() for pattern in suspicious_patterns):
                return True
        
        return False
    
    def handle_forbidden(self, error):
        """Handle 403 Forbidden errors"""
        return jsonify({'error': 'Access forbidden'}), 403
    
    def handle_not_found(self, error):
        """Handle 404 Not Found errors"""
        return jsonify({'error': 'Resource not found'}), 404
    
    def handle_internal_error(self, error):
        """Handle 500 Internal Server errors"""
        logger.error(f"Internal server error: {str(error)}")
        return jsonify({'error': 'Internal server error'}), 500

class RateLimitMiddleware:
    """Rate limiting middleware"""
    
    def __init__(self, app=None):
        self.app = app
        self.requests = {}
        self.limits = {
            'login': {'limit': 20, 'window': 300},  # 20 attempts per 5 minutes
            'otp': {'limit': 10, 'window': 60},     # 10 attempts per minute
            'api': {'limit': 1000, 'window': 3600}, # 1000 requests per hour
            'default': {'limit': 200, 'window': 60} # 200 requests per minute
        }
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        app.before_request(self.check_rate_limit)
    
    def check_rate_limit(self):
        """Check if request exceeds rate limit"""
        # Skip rate limiting for static files and development
        if request.endpoint and request.endpoint.startswith('static'):
            return
        
        # Skip rate limiting in development mode
        if current_app.config.get('DEBUG', False):
            return
        
        # Determine rate limit type
        limit_type = self.get_limit_type()
        limit_config = self.limits.get(limit_type, self.limits['default'])
        
        # Get client identifier
        client_id = self.get_client_id()
        
        # Check rate limit
        if not self.is_allowed(client_id, limit_config):
            logger.warning(f"Rate limit exceeded for {client_id}")
            return jsonify({'error': 'Rate limit exceeded'}), 429
    
    def get_limit_type(self):
        """Determine rate limit type based on request"""
        if request.endpoint == 'login':
            return 'login'
        elif request.endpoint == 'verify':
            return 'otp'
        elif request.path.startswith('/api/'):
            return 'api'
        return 'default'
    
    def get_client_id(self):
        """Get unique client identifier"""
        # Use IP address as primary identifier
        client_id = request.remote_addr
        
        # Add user ID if logged in
        if 'user_id' in session:
            client_id += f"_{session['user_id']}"
        
        return client_id
    
    def is_allowed(self, client_id, limit_config):
        """Check if client is within rate limit"""
        now = time.time()
        window_start = now - limit_config['window']
        
        # Clean old entries
        if client_id in self.requests:
            self.requests[client_id] = [
                timestamp for timestamp in self.requests[client_id]
                if timestamp > window_start
            ]
        else:
            self.requests[client_id] = []
        
        # Check limit
        if len(self.requests[client_id]) >= limit_config['limit']:
            return False
        
        # Add current request
        self.requests[client_id].append(now)
        return True

class LoggingMiddleware:
    """Enhanced logging middleware"""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        app.before_request(self.before_request)
        app.after_request(self.after_request)
    
    def before_request(self):
        """Setup request logging context"""
        g.user_id = session.get('user_id')
        g.phone = session.get('phone')
        g.is_admin = session.get('is_admin', False)
    
    def after_request(self, response):
        """Log request completion"""
        # Log business events
        if hasattr(g, 'business_event'):
            self.log_business_event(g.business_event)
        
        return response
    
    def log_business_event(self, event):
        """Log business-specific events"""
        log_data = {
            'event_type': event.get('type'),
            'user_id': g.user_id,
            'phone': g.phone,
            'details': event.get('details', {}),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        logger.info(f"Business Event: {json.dumps(log_data)}")

class ErrorHandlingMiddleware:
    """Centralized error handling middleware"""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        app.register_error_handler(Exception, self.handle_exception)
        app.register_error_handler(400, self.handle_bad_request)
        app.register_error_handler(401, self.handle_unauthorized)
        app.register_error_handler(403, self.handle_forbidden)
        app.register_error_handler(404, self.handle_not_found)
        app.register_error_handler(429, self.handle_rate_limit)
        app.register_error_handler(500, self.handle_internal_error)
    
    def handle_exception(self, error):
        """Handle unhandled exceptions"""
        logger.error(f"Unhandled exception: {str(error)}", exc_info=True)
        
        # Don't expose internal errors in production
        if current_app.config.get('ENV') == 'production':
            return jsonify({'error': 'Internal server error'}), 500
        else:
            return jsonify({'error': str(error)}), 500
    
    def handle_bad_request(self, error):
        """Handle 400 Bad Request errors"""
        return jsonify({'error': 'Bad request'}), 400
    
    def handle_unauthorized(self, error):
        """Handle 401 Unauthorized errors"""
        return jsonify({'error': 'Unauthorized'}), 401
    
    def handle_forbidden(self, error):
        """Handle 403 Forbidden errors"""
        return jsonify({'error': 'Forbidden'}), 403
    
    def handle_not_found(self, error):
        """Handle 404 Not Found errors"""
        return jsonify({'error': 'Not found'}), 404
    
    def handle_rate_limit(self, error):
        """Handle 429 Rate Limit errors"""
        return jsonify({'error': 'Rate limit exceeded'}), 429
    
    def handle_internal_error(self, error):
        """Handle 500 Internal Server errors"""
        logger.error(f"Internal server error: {str(error)}")
        return jsonify({'error': 'Internal server error'}), 500

def log_business_event(event_type, details=None):
    """Helper function to log business events"""
    g.business_event = {
        'type': event_type,
        'details': details or {}
    }

def require_json(f):
    """Decorator to require JSON content type"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        return f(*args, **kwargs)
    return decorated_function

def validate_request_size(max_size=1024 * 1024):  # 1MB default
    """Decorator to validate request size"""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if request.content_length and request.content_length > max_size:
                return jsonify({'error': 'Request too large'}), 413
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def sanitize_input(input_string):
    """Sanitize user input"""
    if not input_string:
        return ""
    
    # Remove potentially dangerous characters
    dangerous_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '{', '}', '[', ']']
    sanitized = str(input_string)
    
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    return sanitized.strip()
