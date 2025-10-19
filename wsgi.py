#!/usr/bin/env python3
"""
WSGI entry point for production deployment
"""
import os
from app import app

if __name__ == "__main__":
    # For production deployment with gunicorn
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)
