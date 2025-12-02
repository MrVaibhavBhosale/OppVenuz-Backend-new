from django.urls import path
from .views import (
    ImageUploadView,
    UserRegistrationView,
)

urlpatterns = [
    path("v1/uploadImageToS3", ImageUploadView.as_view(), name="upload-image-to-s3"),
    path("userregister/", UserRegistrationView.as_view(), name="user-register"),
 
    
]
