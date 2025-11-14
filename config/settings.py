import os
from pathlib import Path
from decouple import config

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = config("SECRET_KEY")

DEBUG = False

ALLOWED_HOSTS = [
    "*",
]

# -----------------------------
# STATIC FILES (REQUIRED FOR RENDER)
# -----------------------------
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')

# -----------------------------
# MEDIA FILES (if needed later)
# -----------------------------
MEDIA_URL = "/media/"
MEDIA_ROOT = os.path.join(BASE_DIR, "media")

# -----------------------------
# AMAZON S3 CONFIG (Boto3)
# -----------------------------
AWS_ACCESS_KEY_ID = config("s3AccessKey")
AWS_SECRET_ACCESS_KEY = config("s3Secret")
AWS_STORAGE_BUCKET_NAME = config("S3_BUCKET_NAME")
AWS_S3_REGION_NAME = "ap-south-1"

AWS_S3_CUSTOM_DOMAIN = f"{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com"

# Upload folder inside bucket
AWS_LOCATION = "uploads"

# Final media URL (your S3 URL)
MEDIA_URL = f"https://{AWS_S3_CUSTOM_DOMAIN}/{AWS_LOCATION}/"

DEFAULT_FILE_STORAGE = "storages.backends.s3boto3.S3Boto3Storage"

# -----------------------------
# DATABASE (Render uses Postgres)
# -----------------------------
import dj_database_url

DATABASES = {
    "default": dj_database_url.config(
        default=config("DATABASE_URL"),
        conn_max_age=600
    )
}

# -----------------------------
# CORS (important for React/Next)
# -----------------------------
CORS_ALLOW_ALL_ORIGINS = True

# -----------------------------
# INSTALLED_APPS
# -----------------------------
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Third party
    'rest_framework',
    'corsheaders',
    'storages',

    # Your apps
    'admin_master',
    'vendor',
    'user',
    'utilities',
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
]

ROOT_URLCONF = 'config.urls'

WSGI_APPLICATION = 'config.wsgi.application'
