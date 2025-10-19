#!/bin/bash

# RazilHub Production Deployment Script
set -e

echo "🚀 RazilHub Production Deployment Script"
echo "========================================"

# Configuration
APP_NAME="razilhub"
APP_USER="www-data"
APP_DIR="/opt/razilhub"
VENV_DIR="$APP_DIR/venv"
SERVICE_FILE="/etc/systemd/system/razilhub.service"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root"
   exit 1
fi

# Update system packages
print_status "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install required system packages
print_status "Installing system dependencies..."
sudo apt install -y python3 python3-pip python3-venv nginx git

# Create application directory
print_status "Creating application directory..."
sudo mkdir -p $APP_DIR
sudo chown $USER:$USER $APP_DIR

# Copy application files
print_status "Copying application files..."
cp -r . $APP_DIR/
cd $APP_DIR

# Create virtual environment
print_status "Creating virtual environment..."
python3 -m venv $VENV_DIR
source $VENV_DIR/bin/activate

# Install Python dependencies
print_status "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create application user
print_status "Creating application user..."
sudo useradd -r -s /bin/false $APP_USER || true

# Set permissions
print_status "Setting permissions..."
sudo chown -R $APP_USER:$APP_USER $APP_DIR
sudo chmod -R 755 $APP_DIR

# Create necessary directories
print_status "Creating application directories..."
sudo -u $APP_USER mkdir -p $APP_DIR/logs
sudo -u purge $APP_USER mkdir -p $APP_DIR/uploads
sudo -u $APP_USER mkdir -p $APP_DIR/backups

# Setup environment file
print_status "Setting up environment configuration..."
if [ ! -f $APP_DIR/.env ]; then
    sudo -u $APP_USER cp $APP_DIR/environment.template $APP_DIR/.env
    print_warning "Please update $APP_DIR/.env with your production configuration"
fi

# Initialize database
print_status "Initializing database..."
sudo -u $APP_USER $VENV_DIR/bin/python $APP_DIR/app.py --init-db || true

# Install systemd service
print_status "Installing systemd service..."
sudo cp $APP_DIR/razilhub.service $SERVICE_FILE
sudo systemctl daemon-reload
sudo systemctl enable $APP_NAME

# Configure nginx
print_status "Configuring nginx..."
sudo cp $APP_DIR/nginx.conf /etc/nginx/sites-available/$APP_NAME
sudo ln -sf /etc/nginx/sites-available/$APP_NAME /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

# Start services
print_status "Starting services..."
sudo systemctl start $APP_NAME

# Check service status
print_status "Checking service status..."
sudo systemctl status $APP_NAME --no-pager

print_status "Deployment completed successfully!"
echo ""
echo "📋 Access Information:"
echo "   Web Interface: http://your-domain.com"
echo "   Admin Login: 0540000000"
echo "   Service Status: sudo systemctl status razilhub"
echo "   Logs: sudo journalctl -u razilhub -f"