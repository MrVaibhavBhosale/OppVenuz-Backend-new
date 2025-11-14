from pathlib import Path
import os
from dotenv import load_dotenv
from datetime import timedelta

# Load .env file
load_dotenv()

BASE_DIR = Path(__file__).resolve(strict=True).parent.parent

# Security
SECRET_KEY = os.getenv('SECRET_KEY', 'dummy-secret-key')
DEBUG = False
ALLOWED_HOSTS = ["OppVenuz-Backend-new.onrender.com"]

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL")
TEXT_LOCAL_API_KEY = os.getenv("TEXT_LOCAL_API_KEY")
TEXTLOCAL_SENDER = os.getenv("TEXTLOCAL_SENDER", "OPPVNZ")

# Authentication
AUTHENTICATION_BACKENDS = [
    'vendor.auth_backend.VendorAuthBackend',       # Custom vendor backend
    'django.contrib.auth.backends.ModelBackend',   # Default backend
]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "vendor.authentication.VendorJWTAuthentication",  # Custom JWT auth
        "rest_framework_simplejwt.authentication.JWTAuthentication",  # Fallback
    ),
}

# Simple JWT settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
}

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'drf_yasg',
    'admin_master',
    'rest_framework',
    "oauth2_provider",
    'vendor',
    'user',
    'corsheaders',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',  
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'config.middleware.swagger_auto_bearer',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

# Swagger settings
SWAGGER_SETTINGS = {
    'SECURITY_DEFINITIONS': {
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header'
        }
    },
    'SECURITY_REQUIREMENTS': [{'Bearer': []}],
    'USE_SESSION_AUTH': False,
    'SHOW_REQUEST_HEADERS': True,
}

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME'),
        'USER': os.getenv('DB_USER'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': os.getenv('DB_HOST'),
        'PORT': os.getenv('DB_PORT'),
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',},
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# Static and media files
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Upload limits
DATA_UPLOAD_MAX_MEMORY_SIZE = 52428800  # 50 MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 52428800  # 50 MB

# Logging
LOGGING_DIR = os.path.join(BASE_DIR, "log")
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {"format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"},
    },
    "handlers": {
        "debug": {"level": "DEBUG", "class": "logging.handlers.RotatingFileHandler",
                  "filename": os.path.join(LOGGING_DIR, "debug_logs/debug.log"), "backupCount": 10,
                  "maxBytes": 5*1024*1024, "formatter": "standard"},
        "info": {"level": "INFO", "class": "logging.handlers.RotatingFileHandler",
                 "filename": os.path.join(LOGGING_DIR, "info_logs/info.log"), "backupCount": 10,
                 "maxBytes": 5*1024*1024, "formatter": "standard"},
        "warning": {"level": "WARNING", "class": "logging.handlers.RotatingFileHandler",
                    "filename": os.path.join(LOGGING_DIR, "warning_logs/warning.log"), "backupCount": 10,
                    "maxBytes": 5*1024*1024, "formatter": "standard"},
        "error": {"level": "ERROR", "class": "logging.handlers.RotatingFileHandler",
                  "filename": os.path.join(LOGGING_DIR, "error_logs/error.log"), "backupCount": 10,
                  "maxBytes": 5*1024*1024, "formatter": "standard"},
        "critical": {"level": "CRITICAL", "class": "logging.handlers.RotatingFileHandler",
                     "filename": os.path.join(LOGGING_DIR, "critical_logs/critical.log"), "backupCount": 10,
                     "maxBytes": 5*1024*1024, "formatter": "standard"},
    },
    "loggers": {
        "django": {"handlers": ["debug","info","warning","error","critical"], "level": "INFO", "propagate": False},
    },
}

# CORS
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
CORS_ALLOW_CREDENTIALS = True
