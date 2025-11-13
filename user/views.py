from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny

import boto3
from django.conf import settings
from decouple import config
from rest_framework_simplejwt.authentication import JWTAuthentication
from oauth2_provider.contrib.rest_framework.authentication import OAuth2Authentication


class ImageUploadView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = (OAuth2Authentication, JWTAuthentication)

    def post(self, request, *args, **kwargs):
        image = request.FILES.get("image")
        bucket = config("S3_BUCKET_NAME")
        key = request.data.get("key")

        if image:
            # Upload the image to S3 using boto3
            s3 = boto3.client(
                "s3",
                aws_access_key_id=config("s3AccessKey"),
                aws_secret_access_key=config("s3Secret"),
            )
            key = f"{image.name}"  # Change the key as needed
            s3.upload_fileobj(image, bucket, key, ExtraArgs={"ACL": "public-read"})

            # Generate the URL for the uploaded image
            url = f"https://{bucket}.s3.amazonaws.com/{key}"

            return Response({"url": url}, status=status.HTTP_201_CREATED)
        else:
            return Response(
                {"error": "No image provided"}, status=status.HTTP_400_BAD_REQUEST
            )
