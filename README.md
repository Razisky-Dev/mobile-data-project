# RazilHub - Mobile Data Vending Platform

A complete, production-ready Flask application for vending mobile data packages across Ghana's major networks (MTN, Telecel, and AirtelTigo) with additional services.

## 🚀 Features

- **Multi-Network Data Vending**: MTN, Telecel, and AirtelTigo data packages
- **Secure Authentication**: OTP-based login system
- **Wallet System**: Balance management with transaction history
- **Admin Dashboard**: Complete administrative interface
- **Service Booking**: Car wash, delivery, and food ordering
- **Production Ready**: Docker, Nginx, SSL support
- **API Endpoints**: REST API for mobile integration

## 📋 Quick Start

### Single Command Setup & Run
```bash
# Clone repository
git clone <repository-url>
cd mobile-data-project

# Run application (auto-detects Docker, installs dependencies, sets up environment)
python3 run.py
```

### Alternative Commands
```bash
# Setup only (no start)
python3 run.py --setup

# Force Docker mode
python3 run.py --docker

# Force Python mode (no Docker)
python3 run.py --no-docker

# Production mode
python3 run.py --production
```

### Access Application
- **Main App**: http://localhost:5001
- **Admin Login**: 0540000000 (use displayed OTP)

## 🐳 Docker Deployment

```bash
# Using Docker Compose
docker-compose up -d

# Manual Docker build
docker build -t razilhub .
docker run -p 5001:5001 razilhub
```

## 🏗️ Production Deployment

```bash
# Automated deployment
chmod +x deploy.sh
./deploy.sh

# Manual steps
pip install -r requirements.txt
cp environment.template .env  # Update with your config
python3 app.py  # Initialize database
gunicorn wsgi:app
```

## 📊 Supported Networks

| Network | 1GB | 2GB | 3GB | 5GB |
|---------|-----|-----|-----|-----|
| MTN | GHS 10 | GHS 18 | - | GHS 40 |
| Telecel | GHS 9 | - | GHS 25 | GHS 40 |
| AirtelTigo | GHS 8 | - | GHS 22 | GHS 35 |

## 🔧 Configuration

### Environment Variables
Copy `environment.template` to `.env` and configure:

```bash
# Core settings
SECRET_KEY=your-secret-key
DATABASE_URL=sqlite:///data_vending.db
FLASK_ENV=production

# SMS/OTP (optional)
TWILIO_ACCOUNT_SID=your-twilio-sid
AFRICASTALKING_API_KEY=your-api-key

# Payment gateways (optional)
MTN_MOMO_API_KEY=your-momo-key
STRIPE_SECRET_KEY=your-stripe-key
```

## 📱 API Endpoints

```bash
# Authentication
POST /api/auth/login
POST /api/auth/verify

# Data purchase
POST /api/data/purchase

# Wallet management
GET /api/user/balance
POST /api/wallet/deposit

# Health check
GET /health
```

## 🛡️ Security Features

- Input validation and sanitization
- Rate limiting and brute force protection
- CSRF protection
- Secure session management
- SQL injection prevention
- XSS protection

## 📈 Monitoring

```bash
# Health check
curl http://localhost:5001/health

# View logs
tail -f logs/razilhub.log

# Service status
sudo systemctl status razilhub
```

## 🔄 Backup

```bash
# Manual backup
cp data_vending.db backups/backup_$(date +%Y%m%d).db

# Automated backup (via cron)
python3 backup.py
```

## 📞 Support

- **Email**: support@razilhub.com
- **Documentation**: See environment.template for full configuration options

## 📄 License

MIT License

---

**Note**: Ensure you configure all environment variables before deploying to production.