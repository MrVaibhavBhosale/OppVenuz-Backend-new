from django.urls import path
from .views import (
    ImageUploadView,
)

urlpatterns = [
    path("v1/uploadImageToS3", ImageUploadView.as_view(), name="upload-image-to-s3"),
]
