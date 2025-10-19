#!/usr/bin/env python3
"""
RazilHub - Single Source Application Runner
This is the ONLY way to run the RazilHub application
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path

def check_requirements():
    """Check if all requirements are met"""
    print("🔍 Checking requirements...")
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        return False
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}")
    
    # Check if Flask is installed
    try:
        import flask
        print("✅ Flask is available")
    except ImportError:
        print("📦 Installing dependencies...")
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], 
                          check=True, capture_output=True)
            print("✅ Dependencies installed")
        except subprocess.CalledProcessError:
            print("❌ Failed to install dependencies")
            return False
    
    return True

def setup_environment():
    """Setup application environment"""
    print("🔧 Setting up environment...")
    
    # Create necessary directories
    directories = ['logs', 'uploads', 'backups']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    
    # Create .env file if it doesn't exist
    if not Path('.env').exists():
        if Path('environment.template').exists():
            print("📝 Creating .env file from template...")
            with open('environment.template', 'r') as template:
                content = template.read()
            with open('.env', 'w') as env_file:
                env_file.write(content)
            print("✅ .env file created")
        else:
            print("⚠️  No environment template found, using defaults")
    
    print("✅ Environment setup complete")

def run_application(port=5001, host='127.0.0.1', debug=True):
    """Run the RazilHub application"""
    print("\n🚀 Starting RazilHub Mobile Data Vending Platform...")
    print("=" * 60)
    print(f"📍 URL: http://{host}:{port}")
    print("🔧 Admin login: 0540000000 (use displayed OTP)")
    print("💡 Press Ctrl+C to stop")
    print("=" * 60)
    
    try:
        # Import and run the app
        from app import app
        
        app.run(
            host=host,
            port=port,
            debug=debug,
            use_reloader=True,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\n🛑 Application stopped by user")
    except Exception as e:
        print(f"❌ Failed to start application: {e}")
        return False
    
    return True

def run_docker():
    """Run application using Docker"""
    print("🐳 Starting with Docker...")
    
    # Check if Docker is available
    try:
        subprocess.run(['docker', '--version'], check=True, capture_output=True)
        print("✅ Docker is available")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ Docker is not available. Install Docker or use --no-docker flag")
        return False
    
    # Check if Docker daemon is running
    try:
        subprocess.run(['docker', 'info'], check=True, capture_output=True)
        print("✅ Docker daemon is running")
    except subprocess.CalledProcessError:
        print("❌ Docker daemon is not running. Start Docker Desktop or Docker service")
        return False
    
    # Run with Docker Compose
    try:
        print("🚀 Starting with Docker Compose...")
        subprocess.run(['docker-compose', 'up', '--build'], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Docker Compose failed: {e}")
        return False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='RazilHub Application Runner')
    parser.add_argument('--docker', action='store_true', help='Run with Docker')
    parser.add_argument('--no-docker', action='store_true', help='Force run without Docker')
    parser.add_argument('--port', type=int, default=5001, help='Port to run on')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--production', action='store_true', help='Run in production mode')
    parser.add_argument('--setup', action='store_true', help='Run setup only')
    
    args = parser.parse_args()
    
    print("🚀 RazilHub Application Runner")
    print("=" * 40)
    
    # Run setup
    if not check_requirements():
        sys.exit(1)
    
    setup_environment()
    
    if args.setup:
        print("✅ Setup complete. Run without --setup to start the application.")
        return
    
    # Determine how to run
    if args.docker or (not args.no_docker and Path('docker-compose.yml').exists()):
        if run_docker():
            return
        else:
            print("⚠️  Docker failed, falling back to direct Python execution...")
    
    # Run directly with Python
    debug_mode = not args.production
    if not run_application(args.port, args.host, debug_mode):
        sys.exit(1)

if __name__ == "__main__":
    main()
