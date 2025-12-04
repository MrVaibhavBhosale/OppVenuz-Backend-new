from django.urls import path
from .views import (
    ImageUploadView,
    UserRegistrationView,
    CreateOrderAPIView
)

urlpatterns = [
    path("v1/uploadImageToS3", ImageUploadView.as_view(), name="upload-image-to-s3"),
    path("userregister/", UserRegistrationView.as_view(), name="user-register"),
    path("createOrder/", CreateOrderAPIView.as_view(), name="create-order")
    
]
