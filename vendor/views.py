from django.http import JsonResponse
from rest_framework import generics, permissions, status
from django.db import transaction
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.utils import timezone
from admin_master.models import CompanyTypeMaster, StatusMaster
from admin_master.utils import get_status
from decouple import config
from oauth2_provider.contrib.rest_framework.authentication import OAuth2Authentication
from vendor.authentication import VendorJWTAuthentication
from datetime import timedelta
import traceback
from concurrent.futures import ThreadPoolExecutor
from .permissions import IsVendor
import json
from rest_framework.exceptions import PermissionDenied

from .models import (
    Vendor, 
    VendorDevice, 
    Vendor_registration, 
    PhoneVerification,
    EmailVerification,
    VendorDocument,
    VenderBusinessDescription,
    ReadyToSellItem,
    VendorSocialMedia,
    VendorMedia,
    VendorService
)

from .serializers import (
    VendorSerializer,
    VendorBasicSerializer,
    VenderBusinessDescriptionSerializer,
    VendorSignupSerializer,
    VendorLoginSerializer,
    VendorDataSerializer,
    VerifyEmailOTPSerializer,
    VerifyPhoneOTPSerializer,
    RequestEmailOTPSerializer,
    RequestPhoneOTPSerializer,
    VendorDocumentSerializer,
    ForgotMPINRequestSerializer,
    ChangeMPINSerializer,
    ReadyToSellItemSerializer,
    VendorRegistrationSerializer,
    VendorBasicDetailsSerializer,
    VendorSocialMediaSerializer,
    VendorMediaSerializer,
    VendorServiceSerializer,
    VendorContactUpdateSerializer,


)

from .utils import (
    generate_numeric_otp,
    send_otp_email, 
    send_otp_sms,
    mask_email,
    mask_phone
)
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from user_agents import parse
from drf_yasg.utils import swagger_auto_schema
from django.utils.decorators import method_decorator
import logging
import boto3
import uuid
import os
from rest_framework.views import APIView
logger = logging.getLogger("django")


class VendorBasicDetailsAPI(generics.CreateAPIView, generics.UpdateAPIView):
    serializer_class = VendorBasicSerializer
    permission_classes = [permissions.AllowAny]
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            "status": "success",
            "message": "Vendor basic details created successfully",
            "data": serializer.data
        }, status=status.HTTP_201_CREATED)
    
    def update(self, request, *args, **kwargs):
        instance = Vendor.objects.get(id=kwargs.get('id'))
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            "status": "success",
            "message": "Vendor basic details updated successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)
    
@method_decorator(name='put', decorator=swagger_auto_schema(tags=['Vendor Details']))
class VendorDescriptionAPI(generics.UpdateAPIView):
    serializer_class = VenderBusinessDescriptionSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    queryset = VenderBusinessDescription.objects.all()
    lookup_field = "vendor_reg_id"

    def update(self, request, *args, **kwargs):
        vendor_reg_id = kwargs.get("vendor_reg_id")

        # Check if vendor exists
        try:
            vendor = Vendor_registration.objects.get(vendor_id=vendor_reg_id)
        except Vendor_registration.DoesNotExist:
            return Response(
                {"status": "error", "message": "Vendor not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        #find existing record
        description_record = VenderBusinessDescription.objects.filter(vendor_reg_id=vendor_reg_id).first()

        if description_record:
            serializer = self.get_serializer(description_record, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save(updated_by=request.user.username if request.user else None)
            message = "Vendor description updated successfully"
        else:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save(
                vendor=vendor,
                vendor_reg_id=vendor.vendor_id, 
                created_by=request.user.username if request.user else None
            )
            message = "Vendor description created successfully"

        return Response(
            {
                "status": "success",
                "message": message,
                "data": serializer.data
            },
            status=status.HTTP_200_OK
        )
@method_decorator(name='get', decorator=swagger_auto_schema(tags=['Vendor Details']))
class GetVendorDescriptionAPI(generics.ListAPIView):
    serializer_class = VenderBusinessDescriptionSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = VenderBusinessDescription.objects.filter(status=1).order_by('-id')

        # Filter by vendor_id if provided
        vendor_id = self.request.query_params.get('vendor_id', None)
        if vendor_id:
            queryset = queryset.filter(vendor_id=vendor_id)
            if not queryset.exists():
                logger.warning(f"No details found for vendor_id: {vendor_id}")
            return Response({
                "error": "No details found for vendor_id {vendor_id}"
            }, status=status.HTTP_404_NOT_FOUND)
        return queryset

    def list(self, request, *args, **kwargs):
        serializer = self.get_serializer(self.get_queryset(), many=True)
        return Response({
            "status": True,
            "message": "Details fetched successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

class VendorListCreateAPI(generics.ListCreateAPIView):
    serializer_class = VendorSerializer
    permission_classes = [permissions.AllowAny]
    queryset = Vendor.objects.all()

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            "status": "success",
            "message": "Fetched all vendors",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            "status": "success",
            "message": "Vendor created successfully",
            "data": serializer.data
        }, status=status.HTTP_201_CREATED)

class VendorRetrieveUpdateDeleteAPI(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = VendorSerializer
    permission_classes = [permissions.AllowAny]
    queryset = Vendor.objects.all()
    lookup_field = "id"

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response({
            "status": "success",
            "message": "Vendor fetched successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            "status": "success",
            "message": "Vendor updated successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response({
            "status": "success",
            "message": "Vendor deleted successfully"
        }, status=status.HTTP_200_OK)
    
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['Vendor Signup']))
class VendorSignupView(generics.GenericAPIView):
    serializer_class = VendorSignupSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "status": False,
                "message": "Validation failed.",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        contact_no = serializer.validated_data.get("contact_no")
        documents_data = request.data.get("documents", [])

        # Check TEMP documents
        uploaded_docs = VendorDocument.objects.filter(
            vendor_business_no=str(contact_no),
            status="TEMP"
        )
        if not uploaded_docs.exists():
            return Response({
                "error": "Please upload at least one document before registration."
            }, status=status.HTTP_400_BAD_REQUEST)

        matched_doc_ids = []
        for doc in documents_data:
            doc_type = str(doc.get("document_type", "")).strip()
            doc_url = str(doc.get("document_url", "")).strip()

            matching_docs = uploaded_docs.filter(
                document_type__iexact=doc_type,
                document_url__iexact=doc_url
            )
            if matching_docs.exists():
                matched_doc_ids.extend(list(matching_docs.values_list("id", flat=True)))

        matched_doc_ids = list(set(matched_doc_ids))  # remove duplicates

        # Collect device info
        user_agent_string = request.META.get('HTTP_USER_AGENT', '')
        user_agent = parse(user_agent_string)
        if user_agent.is_mobile:
            device_type = "Mobile"
        elif user_agent.is_tablet:
            device_type = "Tablet"
        elif user_agent.is_pc:
            device_type = "Desktop"
        else:
            device_type = "Other"
            
        os_family = user_agent.os.family or ""
        if "Android" in os_family:
            os_type = "Android"
        elif "iOS" in os_family:
            os_type = "iOS"
        else:
            os_type = os_family or "Other"

        device_info = {
            "device_type": device_type,
            "os_version": user_agent.os.version_string,
            "browser_name": user_agent.browser.family,
            "browser_version": user_agent.browser.version_string,
            "os_type": os_type,
        }

        # All checks done, now save
        vendor = serializer.save()
        if matched_doc_ids:
            VendorDocument.objects.filter(id__in=matched_doc_ids).update(status="PERMANENT")
            vendor.document_id = matched_doc_ids
            vendor.save(update_fields=["document_id"])

        VendorDevice.objects.update_or_create(
            vendor_id=vendor,
            device_type=device_info["device_type"],
            os_version=device_info["os_version"],
            browser_name=device_info["browser_name"],
            os_type=device_info["os_type"],
            defaults={"browser_version": device_info["browser_version"]}
        )

        refresh = RefreshToken.for_user(vendor)
        vendor_data = self.get_serializer(vendor).data
        vendor_data.update({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "device_info": device_info
        })

        return Response({
            "status": True,
            "message": "Vendor registered successfully.",
            "data": vendor_data
        }, status=status.HTTP_201_CREATED)



@method_decorator(name='post', decorator=swagger_auto_schema(tags=['Vendor login']))
class VendorLoginView(generics.GenericAPIView):
    serializer_class = VendorLoginSerializer
    permission_classes = [AllowAny]
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():
            return Response({
                "status": False,
                "message": "Invalid credentials",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data['user']

        user_agent_string = request.META.get('HTTP_USER_AGENT', '')
        user_agent = parse(user_agent_string)

        if user_agent.is_mobile:
            device_type = "Mobile"
        elif user_agent.is_tablet:
            device_type = "Tablet"
        elif user_agent.is_pc:
            device_type = "Desktop"
        else:
            device_type = "Other"

        os_family = user_agent.os.family or ""
        if "Android" in os_family:
            os_type = "Android"
        elif "iOS" in os_family:
            os_type = "iOS"
        else:
            os_type = os_family or "Other"

        device_info = {
        "device_type": device_type,
        "os_version": user_agent.os.version_string,
        "browser_name": user_agent.browser.family,
        "browser_version": user_agent.browser.version_string,
        "os_type": os_type

        }

        # Save or update device
        VendorDevice.objects.update_or_create(
            vendor_id=user,
            device_type=device_info["device_type"],
            os_version=device_info["os_version"],
            browser_name=device_info["browser_name"],
            os_type=device_info["os_type"],
            defaults={
                "browser_version": device_info["browser_version"],
            }
            )
        
        refresh = RefreshToken.for_user(user)

        vendor_data = VendorDataSerializer(user).data
        vendor_data.update({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "device_info": device_info
        })

        return Response({
            "status": True,
            "message": "Login successful",
            "data": vendor_data
        }, status=status.HTTP_200_OK)


@method_decorator(name='post', decorator=swagger_auto_schema(tags=['sendEmail- otp']))
class RequestEmailOTPView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = RequestEmailOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get('email')
        masked_email = mask_email(email)

        try:
            with transaction.atomic():
                # Get or create verification record first
                verification, created = EmailVerification.objects.get_or_create(email=email)

                if verification.is_verified:
                    return Response({
                        "status": True,
                        "message": "Email already verified.",
                        "email": masked_email,
                        "is_email_verified": True
                    }, status=status.HTTP_200_OK)

                 # Check if the user is temporarily blocked
                remaining_block = verification._is_blocked()
                if remaining_block:
                    return Response({
                        "status": False,
                        "message": f"Too many failed attempts. Try again after {remaining_block} seconds."
                    }, status=status.HTTP_403_FORBIDDEN)
                
                # Cooldown check (60 seconds)
                if not verification.can_request_new_otp():
                    return Response({
                        "status": False,
                        "message": "Please wait at least 60 seconds before requesting another OTP."
                    }, status=status.HTTP_429_TOO_MANY_REQUESTS)

                # generate and set OTP using model method
                otp = str(123456)
                verification.set_otp(otp)

        except Exception as e:
            logger.exception("Error generating email OTP")
            return Response({
                "status": False,
                "message": f"Failed to process OTP: {str(e)}"
            }, status=status.HTTP_400_BAD_REQUEST)

        # send email OTP
        email_sent = send_otp_email(email, otp)
        return Response({
            "status": True,
            "message": f"OTP sent successfully to {masked_email}",
            "email_sent": email_sent == 202
        }, status=status.HTTP_200_OK)

@method_decorator(name='post', decorator=swagger_auto_schema(tags=['sendPhone otp'])) 
class RequestPhoneOTPView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = RequestPhoneOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone = serializer.validated_data.get('phone')
        masked_phone = mask_phone(phone)

        try:
            with transaction.atomic():
                # Get or create verification record first
                verification, created = PhoneVerification.objects.get_or_create(phone=phone)

                if verification.is_verified:
                    return Response({
                        "status": True,
                        "message": "Phone verified Already.",
                        "phone": masked_phone,
                        "is_email_verified": True
                    }, status=status.HTTP_200_OK)

                # Check if the user is temporarily blocked
                remaining_block = verification._is_blocked()
                if remaining_block:
                    return Response({
                        "status": False,
                        "message": f"Too many failed attempts. Try again after {remaining_block} seconds."
                    }, status=status.HTTP_403_FORBIDDEN)
                
                # Cooldown check (60 seconds)
                if not verification.can_request_new_otp():
                    return Response({
                        "status": False,
                        "message": "Please wait at least 60 seconds before requesting another OTP."
                    }, status=status.HTTP_429_TOO_MANY_REQUESTS)

                # Generate and set OTP
                otp = str(123456) #generate_numeric_otp()
                verification.set_otp(otp)

        except Exception as e:
            logger.exception("Error generating phone OTP")
            return Response({
                "status": False,
                "message": f"Failed to process OTP: {str(e)}"
            }, status=status.HTTP_400_BAD_REQUEST)

        # Send SMS OTP
        sms_sent = True #send_otp_sms(phone, otp)

        return Response({
            "status": True,
            "message": f"OTP sent successfully to {masked_phone}",
            "sms_sent": sms_sent
        }, status=status.HTTP_200_OK)
    

@method_decorator(name='post', decorator=swagger_auto_schema(tags=['VerifyOTP - Email']))
class VerifyEmailOTPView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = VerifyEmailOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        raw_otp = serializer.validated_data['otp']
        masked_email = mask_email(email)

        verification = get_object_or_404(EmailVerification, email=email)

        if verification.is_verified:
            return Response({
                "status": True,
                "message": "Email already verified.",
                "email": masked_email,
                "is_email_verified": True
            }, status=status.HTTP_200_OK)

        remaining_block = verification._is_blocked()
        if remaining_block:
            return Response({
                "status": False,
                "message": f"Too many failed attempts. Try again after {remaining_block} seconds."
                }, status=status.HTTP_403_FORBIDDEN)
        
        # validate OTP
        if not verification.check_otp(raw_otp):
            verification.mark_attempt()
            return Response({
                "status": False,
                "message": "Invalid or expired OTP."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # mark email as verified
        with transaction.atomic():
            verified = verification.mark_verified()

        return Response({
            "status": True,
            "message": "Email Verified successfully.",
            "email": masked_email,
            "is_email_verified": verified
        }, status=status.HTTP_200_OK)
    
    
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['VerifyOTP - Phone']))
class VerifyPhoneOTPView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = VerifyPhoneOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone = serializer.validated_data['phone']
        otp = serializer.validated_data['otp']  
        masked_phone = mask_phone(phone)

        verification = get_object_or_404(PhoneVerification, phone=phone)

        if verification.is_verified:
            return Response({
                "status": True,
                "message": "Contact number already verified.",
                "phone": masked_phone,
                "is_phone_verified": True
            }, status=status.HTTP_200_OK)

        #check if temporary blocked
        remaining_block = verification._is_blocked()
        if remaining_block:
            return Response({
                "status": False,
                "message": f"Too many failed attempts. Try again after {remaining_block} seconds."
            }, status=status.HTTP_403_FORBIDDEN)

        #validate OTP
        if not verification.check_otp(otp):
            verification.mark_attempt()
            return Response({
                "status": False,
                "message": "Invalid or Expired OTP."
            },
            status=status.HTTP_400_BAD_REQUEST)
        
        #mark phone as verified
        with transaction.atomic():
            verified = verification.mark_verified()
            
        return Response({
            "status": True,
            "message": "Phone verified successfully.",
            "Phone:": masked_phone,
            "is_phone_verified": verified,
        }, status=status.HTTP_200_OK)

class VendorDocumentUploadAPIView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = (OAuth2Authentication, JWTAuthentication)

    def post(self, request, *args, **kwargs):
        try:
            phone = request.data.get("vendor_business_no")
            document_type = request.data.get("document_type")
            section_type = request.data.get("section_type")
            image = request.FILES.get("file")
            company_type_id = request.data.get("company_type")

            if not all([phone, document_type, image, company_type_id]):
                return Response({"error": "Missing required fields"}, status=status.HTTP_400_BAD_REQUEST)

            # Step 1: Get verification entry using phone
            verification = PhoneVerification.objects.filter(phone=phone, is_verified=True).first()
            if not verification:
                return Response({"error": "Phone number not verified"}, status=status.HTTP_400_BAD_REQUEST)

            # Step 2: Get CompanyTypeMaster instance using id
            try:
                company_type_obj = CompanyTypeMaster.objects.get(id=company_type_id)
            except CompanyTypeMaster.DoesNotExist:
                return Response({"error": "Invalid company_type id"}, status=status.HTTP_400_BAD_REQUEST)

            # Step 3: Delete expired TEMP docs
            now = timezone.now()
            VendorDocument.objects.filter(status='TEMP', expires_at__lt=now).update(status='DELETED')

            # Step 4: Upload to S3
            s3 = boto3.client(
                "s3",
                aws_access_key_id=config("s3AccessKey"),
                aws_secret_access_key=config("s3Secret"),
            )
            bucket = config("S3_BUCKET_NAME")

            # Generate unique filename
            file_ext = os.path.splitext(image.name)[1] 
            unique_name = f"{uuid.uuid4().hex}{file_ext}"  
            key = f"vendor_documents/{phone}/{unique_name}"

            s3.upload_fileobj(image, bucket, key, ExtraArgs={"ACL": "public-read"})
            document_url = f"https://{bucket}.s3.amazonaws.com/{key}"

            # Step 5: Save in DB
            doc = VendorDocument.objects.create(
                verification=verification,
                company_type=company_type_obj,
                document_type=document_type,
                document_url=document_url,
                status="TEMP",
                vendor_business_no=phone,
                expires_at=timezone.now() + timedelta(hours=1),
            )

            serializer = VendorDocumentSerializer(doc)
            return Response({
                "message": f"{document_type} uploaded successfully.",
                "document": serializer.data
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(name='post', decorator=swagger_auto_schema(tags=['ForgotMPIN']))
class ForgotMPINView(APIView):

    def post(self, request):
        serializer = ForgotMPINRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get('email')
        phone = serializer.validated_data.get('phone')

        if email:
            channel = 'email'
            verification = EmailVerification.objects.filter(email=email, is_verified=True).first()
        else:
            channel = 'phone'
            verification = PhoneVerification.objects.filter(phone=phone, is_verified=True).first()

        if not verification:
            return Response({
                "status": False,
                "message": "No verified record found. Please verify your email or phone first."
            }, status=status.HTTP_404_NOT_FOUND)
        
        if verification._is_blocked():
            return Response({
                "status": False,
                "message": "Too many failed attempts. Please try again later."
            }, status=status.HTTP_403_FORBIDDEN)

        if not verification.can_request_new_otp():
            return Response({
                "status": False,
                "message": "Please wait at least 60 seconds before requesting another OTP."
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)

        otp = str(123456) #generate_numeric_otp()
        verification.set_otp(otp)

        # Send OTP
        if channel == 'email':
            email_sent = send_otp_email(email, otp)
            masked_email = mask_email(email)
            message = f"OTP sent successfully to {masked_email}"
            return Response({
                "status": True,
                "message": message,
                "email_sent": email_sent
            }, status=status.HTTP_200_OK)

        else:
            sms_sent = send_otp_sms(phone, otp)
            masked_phone = mask_phone(phone)
            message = f"OTP sent successfully to {masked_phone}"
            return Response({
                "status": True,
                "message": message,
                "sms_sent": True #sms_sent
            }, status=status.HTTP_200_OK)


@method_decorator(name='post', decorator=swagger_auto_schema(tags=['VerifyOTP - Forgot MPIN']))
class VerifyMPINOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')
        phone = request.data.get('phone')
        otp = request.data.get('otp')

        if not otp:
            return Response({
                "status": False,
                "message": "OTP is required."
            }, status=status.HTTP_400_BAD_REQUEST)

        if not email and not phone:
            return Response({
                "status": False,
                "message": "Email or phone is required."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Determine which verification model to use
        if email:
            verification = get_object_or_404(EmailVerification, email=email)
            channel = "email"
            masked_value = mask_email(email)
        else:
            verification = get_object_or_404(PhoneVerification, phone=phone)
            channel = "phone"
            masked_value = mask_phone(phone)

        remaining_block = verification._is_blocked()
        if remaining_block:
            return Response({
                "status": False,
                "message": f"Too many failed attempts. Try again after {remaining_block} seconds."
            }, status=status.HTTP_403_FORBIDDEN)

        if not verification.check_otp(otp):
            verification.mark_attempt()
            return Response({
                "status": False,
                "message": "Invalid or expired OTP."
            }, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            "status": True,
            "message": f"{channel.title()} verified successfully.",
            channel: masked_value,
            f"is_{channel}_verified": True
        }, status=status.HTTP_200_OK)

@method_decorator(name='post', decorator=swagger_auto_schema(tags=['ResetMPIN']))
class ChangeMPINView(APIView):
    def post(self, request):
        serializer = ChangeMPINSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()

            return Response({
                "status": True,
                "message": "MPIN changed successfully."
            },
            status=status.HTTP_200_OK)

        return Response({
            "status": False,
            "errors": serializer.errors
        },
        status=status.HTTP_400_BAD_REQUEST)

class UploadDefaultVendorImageAPIView(APIView):
    permission_classes = [AllowAny] 

    def post(self, request):
        file_obj = request.FILES.get('file')
        if not file_obj:
            return Response({"error": "Please upload a file."}, status=status.HTTP_400_BAD_REQUEST)

        s3 = boto3.client(
            's3',
            aws_access_key_id=os.getenv('s3AccessKey'),
            aws_secret_access_key=os.getenv('s3Secret')
        )

        file_key = os.getenv('DEFAULT_VENDOR_IMAGE_PATH', 'defaults/vendor_default.png')
        bucket_name = os.getenv('S3_BUCKET_NAME')

        try:
            # Upload file to S3 in the defined default path
            s3.upload_fileobj(file_obj, bucket_name, file_key, ExtraArgs={'ACL': 'public-read'})

            image_url = f"https://{bucket_name}.s3.amazonaws.com/{file_key}"

            return Response({
                "status": True,
                "message": "Default vendor image uploaded successfully.",
                "default_image_url": image_url
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({
                "status": False,
                "message": f"Upload failed: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class VendorProfileImageUploadAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        file_obj = request.FILES.get('file')
        if not file_obj:
            return Response({"error": "Please upload an image file."}, status=status.HTTP_400_BAD_REQUEST)

        max_size = 4 * 1024 * 1024
        if file_obj.size > max_size:
            return Response(
                {"error": "File size exceeds 4 MB limit."},
                status=status.HTTP_400_BAD_REQUEST
            )

        vendor = request.user
        s3 = boto3.client(
            's3',
            aws_access_key_id=os.getenv("s3AccessKey"),
            aws_secret_access_key=os.getenv("s3Secret"),
        )

        bucket = os.getenv("S3_BUCKET_NAME")

        ext = os.path.splitext(file_obj.name)[1]
        unique_name = f"{uuid.uuid4().hex}{ext}"

        file_key = f"vendors/{vendor.vendor_id}/{unique_name}"

        try:
            s3.upload_fileobj(file_obj, bucket, file_key, ExtraArgs={'ACL': 'public-read'})
            image_url = f"https://{bucket}.s3.amazonaws.com/{file_key}"

            vendor.profile_image = image_url
            vendor.save(update_fields=['profile_image'])

            return Response({
                "status": True,
                "message": "Profile image uploaded successfully.",
                "profile_image": image_url
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": False,
                "message": f"Upload failed: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VendorProfileImageDeleteAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        vendor = request.user
        default_image = os.getenv('DEFAULT_VENDOR_IMAGE_PATH')

        vendor.profile_image = default_image
        vendor.save(update_fields=['profile_image'])

        return Response({
            "status": True,
            "message": "Profile image reset to default.",
            "profile_image": default_image
        }, status=status.HTTP_200_OK)

# Base class for S3 Upload
class ReadyToSellBaseView(APIView):
    def upload_to_s3(self, file_obj):
        """Uploads a file to S3 and returns its public URL."""
        s3 = boto3.client(
            "s3",
            aws_access_key_id=config("s3AccessKey"),
            aws_secret_access_key=config("s3Secret"),
        )
        bucket = config("S3_BUCKET_NAME")
        key = f"ready_to_sell/{file_obj.name}"
        s3.upload_fileobj(file_obj, bucket, key, ExtraArgs={"ACL": "public-read"})
        return f"https://{bucket}.s3.amazonaws.com/{key}"
    
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['ready_to_sell']))
class CreateReadyToSellItemView(ReadyToSellBaseView):
    authentication_classes = [VendorJWTAuthentication]
    permission_classes = [IsAuthenticated]
    def post(self, request):
        product_name = request.data.get("product_name")
        price = request.data.get("price")
        description = request.data.get("description", "")
        files = request.FILES.getlist("images")

        if not product_name or not price:
            return Response({
                "status": False,
                "message": "Product name and price are required.",
                "data": None
            }, status=status.HTTP_400_BAD_REQUEST)

        allowed_ext = (".png", ".jpg", ".jpeg", ".gif")
        invalid_files = [f.name for f in files if not f.name.lower().endswith(allowed_ext)]
        if invalid_files:
            return Response({
                "status": False,
                "message": f"Invalid file type(s): {', '.join(invalid_files)}. Only images are allowed.",
                "data": None
            }, status=status.HTTP_400_BAD_REQUEST)

        uploaded_urls = []
        if files:
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(self.upload_to_s3, f) for f in files]
                for future in futures:
                    uploaded_urls.append(future.result())

        status_obj = get_status("Active")
        item = ReadyToSellItem.objects.create(
            product_name=product_name.strip(),
            price=price,
            description=description.strip(),
            image_urls=uploaded_urls,
            status=status_obj,
        )

        return Response({
            "status": True,
            "message": "Item created successfully.",
            "data": ReadyToSellItemSerializer(item).data
        }, status=status.HTTP_201_CREATED)

@method_decorator(name="get", decorator=swagger_auto_schema(tags=["ready_to_sell"]))
class GetAllReadyToSellItemsView(generics.ListAPIView):
    serializer_class = ReadyToSellItemSerializer

    def get_queryset(self):
        """Fetch only non-deleted items"""
        active_status = get_status("Active")
        return ReadyToSellItem.objects.filter(status=active_status).order_by("-created_at")

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            "status": True,
            "message": "Active items fetched successfully.",
            "data": serializer.data,
        }, status=status.HTTP_200_OK)

@method_decorator(name="get", decorator=swagger_auto_schema(tags=["ready_to_sell"]))
class GetReadyToSellItemByIDView(generics.RetrieveAPIView):
    serializer_class = ReadyToSellItemSerializer
    lookup_field = "id"

    def get_queryset(self):
        """Exclude deleted items"""
        deleted_status = get_status("Deleted")
        return ReadyToSellItem.objects.exclude(status=deleted_status)

    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_queryset().get(id=kwargs["id"])
        except ReadyToSellItem.DoesNotExist:
            return Response({
                "status": False,
                "message": "Item not found or has been deleted.",
                "data": None,
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(instance)
        return Response({
            "status": True,
            "message": "Item fetched successfully.",
            "data": serializer.data,
        }, status=status.HTTP_200_OK)

@method_decorator(name='put', decorator=swagger_auto_schema(tags=['ready_to_sell']))
class UpdateReadyToSellItemView(ReadyToSellBaseView):
    authentication_classes = [VendorJWTAuthentication]
    permission_classes = [IsAuthenticated]
    def put(self, request, id):
        try:
            item = ReadyToSellItem.objects.get(id=id)
        except ReadyToSellItem.DoesNotExist:
            return Response({
                "status": False,
                "message": "Item not found.",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        product_name = request.data.get("product_name", item.product_name)
        price = request.data.get("price", item.price)
        description = request.data.get("description", item.description)
        status_name = request.data.get("status")

        status_obj = get_status(status_name) if status_name else item.status

        files = request.FILES.getlist("images")
        if files:
            allowed_ext = (".png", ".jpg", ".jpeg", ".gif")
            new_urls = []
            for f in files:
                if not f.name.lower().endswith(allowed_ext):
                    return Response({
                        "status": False,
                        "message": f"Invalid file type for {f.name}.",
                        "data": None
                    }, status=status.HTTP_400_BAD_REQUEST)
                new_urls.append(self.upload_to_s3(f))
            item.image_urls.extend(new_urls)

        item.product_name = product_name
        item.price = price
        item.description = description
        item.status = status_obj
        item.updated_at = timezone.now()
        item.save()

        return Response({
            "status": True,
            "message": "Item updated successfully.",
            "data": ReadyToSellItemSerializer(item).data
        }, status=status.HTTP_200_OK)

@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['ready_to_sell']))
class DeleteReadyToSellItemView(APIView):
    authentication_classes = [VendorJWTAuthentication]
    permission_classes = [IsAuthenticated]
    def delete(self, request, id):
        """
        delete an item by marking its status as 'Deleted'.
        """
        try:
            item = ReadyToSellItem.objects.get(id=id)
        except ReadyToSellItem.DoesNotExist:
            return Response({
                "status": False,
                "message": "Item not found.",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        deleted_status = get_status("Deleted")
        if item.status == deleted_status:
            return Response({
                "status": False,
                "message": "Item is already deleted.",
                "data": None
            }, status=status.HTTP_400_BAD_REQUEST)

        item.status = deleted_status
        item.updated_at = timezone.now()
        item.save(update_fields=["status", "updated_at"])

        return Response({
            "status": True,
            "message": "Item deleted successfully.",
            "data": None
        }, status=status.HTTP_200_OK)
    
class VendorRegistrationProfileAPIView(generics.GenericAPIView):
    authentication_classes = [VendorJWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = VendorRegistrationSerializer

    def get(self, request, *args, **kwargs):
        user_email = getattr(request.user, 'email', None)
        user_username = getattr(request.user, 'username', None)

        vendor = None
        if user_email:
            vendor = Vendor_registration.objects.filter(email__iexact=user_email).first()
        if not vendor and user_username:
            vendor = Vendor_registration.objects.filter(contact_no__iexact=user_username).first()

        if not vendor:
            return Response({
                "status": False,
                "message": "Vendor profile not found for the authenticated user."
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(vendor)
        return Response({
            "status": True,
            "message": "Vendor profile fetched successfully.",
            "data": serializer.data
        }, status=status.HTTP_200_OK)
    
class VendorBasicDetailsUpdateAPIView(generics.UpdateAPIView):
    authentication_classes = [VendorJWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = VendorBasicDetailsSerializer

    def get_object(self):
        user_email = getattr(self.request.user, 'email', None)
        user_username = getattr(self.request.user, 'username', None)

        vendor = None
        if user_email:
            vendor = Vendor_registration.objects.filter(email__iexact=user_email).first()
        if not vendor and user_username:
            vendor = Vendor_registration.objects.filter(contact_no__iexact=user_username).first()

        return vendor

    def update(self, request, *args, **kwargs):
        vendor = self.get_object()
        if not vendor:
            return Response({
                "status": False,
                "message": "Vendor not found."
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(vendor, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "status": True,
                "message": "Basic details updated successfully.",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        return Response({
            "status": False,
            "message": "Validation failed.",
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class VendorSocialMediaView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = VendorSocialMediaSerializer

    def get(self, request):
        try:
            vendor = Vendor_registration.objects.filter(
                email=request.user.email
            ).first()

            if not vendor:
                return Response({
                    "status": False,
                    "message": "Vendor not found for this user."
                }, status=status.HTTP_404_NOT_FOUND)

            social_media, _ = VendorSocialMedia.objects.get_or_create(
                vendor=vendor,
                vendor_reg_id=vendor.vendor_id
            )

            serializer = self.get_serializer(social_media)
            return Response({
                "status": True,
                "message": "Social media details fetched successfully.",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            traceback.print_exc()
            return Response({
                "status": False,
                "message": f"Error fetching social media: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request):
        try:
            vendor = Vendor_registration.objects.filter(
                email=request.user.email
            ).first()

            if not vendor:
                return Response({
                    "status": False,
                    "message": "Vendor not found for this user."
                }, status=status.HTTP_404_NOT_FOUND)

            social_media, created = VendorSocialMedia.objects.get_or_create(
                vendor=vendor,
                vendor_reg_id=vendor.vendor_id
            )

            serializer = self.get_serializer(social_media, data=request.data, partial=True)
            if serializer.is_valid():
                instance = serializer.save(updated_by=request.user.email)

                if created and not instance.created_by:
                    instance.created_by = request.user.email
                    instance.save(update_fields=["created_by"])

                return Response({
                    "status": True,
                    "message": "Social media details updated successfully.",
                    "data": self.get_serializer(instance).data
                }, status=status.HTTP_200_OK)

            return Response({
                "status": False,
                "message": "Invalid data.",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            traceback.print_exc()
            return Response({
                "status": False,
                "message": f"Error updating social media: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class VendorMediaUploadAPIView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = [VendorJWTAuthentication]

    MAX_IMAGE_COUNT = 10
    MAX_VIDEO_COUNT = 3
    MAX_IMAGE_SIZE_MB = 2
    MAX_VIDEO_SIZE_MB = 20

    def post(self, request):
        try:
            vendor_id = request.data.get("vendor_id")  
            media_type = request.data.get("media_type") 
            files = request.FILES.getlist("files")

            if not all([vendor_id, media_type, files]):
                return Response({"error": "Missing required fields"}, status=status.HTTP_400_BAD_REQUEST)

            vendor = Vendor_registration.objects.filter(vendor_id=vendor_id).first()
            if not vendor:
                return Response({"error": "Invalid vendor_id"}, status=status.HTTP_400_BAD_REQUEST)

            existing_count = VendorMedia.objects.filter(vendor_code=vendor_id, media_type=media_type, status="ACTIVE").count()
            if media_type == "IMAGE" and (existing_count + len(files)) > self.MAX_IMAGE_COUNT:
                return Response({"error": f"Max {self.MAX_IMAGE_COUNT} images allowed."}, status=status.HTTP_400_BAD_REQUEST)
            if media_type == "VIDEO" and (existing_count + len(files)) > self.MAX_VIDEO_COUNT:
                return Response({"error": f"Max {self.MAX_VIDEO_COUNT} videos allowed."}, status=status.HTTP_400_BAD_REQUEST)

            for f in files:
                size_mb = f.size / (1024 * 1024)
                if media_type == "IMAGE" and size_mb > self.MAX_IMAGE_SIZE_MB:
                    return Response({"error": f"Each image must be ≤ {self.MAX_IMAGE_SIZE_MB} MB."}, status=status.HTTP_400_BAD_REQUEST)
                if media_type == "VIDEO" and size_mb > self.MAX_VIDEO_SIZE_MB:
                    return Response({"error": f"Each video must be ≤ {self.MAX_VIDEO_SIZE_MB} MB."}, status=status.HTTP_400_BAD_REQUEST)

            s3 = boto3.client(
                "s3",
                aws_access_key_id=config("s3AccessKey"),
                aws_secret_access_key=config("s3Secret"),
            )
            bucket = config("S3_BUCKET_NAME")

            uploaded_files = []
            for file in files:
                ext = os.path.splitext(file.name)[1]
                unique_name = f"{uuid.uuid4().hex}{ext}"
                key = f"vendor_media/{vendor_id}/{unique_name}"

                s3.upload_fileobj(file, bucket, key, ExtraArgs={"ACL": "public-read"})
                file_url = f"https://{bucket}.s3.amazonaws.com/{key}"

                media = VendorMedia.objects.create(
                    vendor=vendor,
                    vendor_code=vendor_id,
                    file_url=file_url,
                    file_name=unique_name,
                    media_type=media_type,
                )
                uploaded_files.append(VendorMediaSerializer(media).data)

            return Response({
                "message": "Media uploaded successfully.",
                "uploaded": uploaded_files
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VendorMediaListAPIView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = [VendorJWTAuthentication]

    def get(self, request, vendor_id):
        media = VendorMedia.objects.filter(vendor_code=vendor_id, status="ACTIVE")
        serializer = VendorMediaSerializer(media, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class VendorMediaDeleteAPIView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = [VendorJWTAuthentication]

    def delete(self, request, pk):
        try:
            media = VendorMedia.objects.get(pk=pk, status="ACTIVE")

            s3 = boto3.client(
                "s3",
                aws_access_key_id=config("s3AccessKey"),
                aws_secret_access_key=config("s3Secret"),
            )
            bucket = config("S3_BUCKET_NAME")
            key = f"vendor_media/{media.vendor_code}/{media.file_name}"

            s3.delete_object(Bucket=bucket, Key=key)

            media.status = "DELETED"
            media.save()

            return Response({"message": "Media deleted successfully"}, status=status.HTTP_200_OK)

        except VendorMedia.DoesNotExist:
            return Response({"error": "Media not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['Product Details']))
class VendorServiceCreateAPIView(generics.CreateAPIView):
    queryset = VendorService.objects.all()
    serializer_class = VendorServiceSerializer
    permission_classes = [IsAuthenticated, IsVendor]

    def post(self, request, *args, **kwargs):
        user = request.user

        # Only vendors can create services
        if not isinstance(user, Vendor_registration):
            return Response(
                {"message": "Only vendors can create product.", "status": False},
                status=status.HTTP_403_FORBIDDEN
            )

        # Parse and validate 'data'
        service_data = request.data.get("data", {})
        if isinstance(service_data, str):
            try:
                service_data = json.loads(service_data)
            except Exception:
                return Response({"message": "Invalid JSON for 'data' field.", "status": False}, status=400)
        if not isinstance(service_data, dict):
            service_data = {}

        if "images" not in service_data or not isinstance(service_data["images"], list):
            service_data["images"] = []

        # Handle S3 images
        images = request.FILES.getlist("image")
        if images:
            s3 = boto3.client(
                "s3",
                aws_access_key_id=config("s3AccessKey"),
                aws_secret_access_key=config("s3Secret"),
            )
            bucket = config("S3_BUCKET_NAME")
            for image in images:
                key = f"vendor_services/{image.name}"
                try:
                    s3.upload_fileobj(
                        Fileobj=image,
                        Bucket=bucket,
                        Key=key,
                        ExtraArgs={"ACL": "public-read", "ContentType": image.content_type}
                    )
                    image_url = f"https://{bucket}.s3.amazonaws.com/{key}"
                    service_data["images"].append(image_url)
                except Exception as e:
                    logger.error(f"S3 upload failed: {str(e)}")

        # Prepare serializer input
        serializer_input = {
            "data": service_data,
            "status": request.data.get("status", 1)
        }

        serializer = self.get_serializer(data=serializer_input, context={"request": request})
        serializer.is_valid(raise_exception=True)
        service = serializer.save()

        response_serializer = self.get_serializer(service)
        return Response({
            "message": "Product created successfully.",
            "data": response_serializer.data,
            "status": True
        }, status=status.HTTP_201_CREATED)
    

@method_decorator(name='get', decorator=swagger_auto_schema(tags=['Product Details']))
class VendorServiceListAPIView(generics.ListAPIView):
    serializer_class = VendorServiceSerializer
    permission_classes = [IsAuthenticated, IsVendor]

    def get_queryset(self):
        vendor = self.request.user
        product_id = self.kwargs.get('product_id')

        if not product_id:
            raise PermissionDenied("Product ID is required.")

        try:
            active_status = StatusMaster.objects.get(status_type__iexact='Active')
        except StatusMaster.DoesNotExist:
            logger.warning("[VendorServiceListAPIView] 'Active' status not found in StatusMaster")
            raise PermissionDenied("Active status not found in the system")

        # Filter by vendor, active status, and product_id inside the data JSONField
        queryset = VendorService.objects.filter(
            vendor_id=vendor.id,
            status=active_status,
            id=product_id  
        )
        return queryset

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True)
            return Response({
                "message": "product fetched successfully",
                "data": serializer.data,
                "status": True
            })
        except PermissionDenied as e:
            logger.warning(f"[VendorServiceListAPIView] Permission denied: {str(e)}")
            return Response({
                "message": str(e),
                "status": False
            }, status=403)
        except Exception as e:
            logger.exception(f"[VendorServiceListAPIView] Unexpected error while listing vendor product: {str(e)}")
            return Response({
                "message": "An unexpected error occurred while fetching vendor Product.",
                "error": str(e),
                "status": False
            }, status=500)


@method_decorator(name='put', decorator=swagger_auto_schema(tags=['Product Details']))
class VendorServiceUpdateAPIView(generics.UpdateAPIView):
    serializer_class = VendorServiceSerializer
    permission_classes = [IsAuthenticated, IsVendor]  

    def get_object(self):
        vendor = self.request.user
        product_id = self.kwargs.get('product_id')

        if not product_id:
            raise PermissionDenied("Product ID is required.")

        # Get active status
        try:
            active_status = StatusMaster.objects.get(status_type__iexact='Active')
        except StatusMaster.DoesNotExist:
            raise PermissionDenied("Active status not found in the system")

        # Fetch the specific service for this vendor
        try:
            service = VendorService.objects.get(
                id=product_id,
                vendor_id=vendor.id,
                status=active_status
            )
        except VendorService.DoesNotExist:
            raise PermissionDenied("Product not found for this vendor.")

        return service

    def update(self, request, *args, **kwargs):
        try:
            service = self.get_object()
            serializer = self.get_serializer(service, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save(updated_by=request.user.username)

            return Response({
                "message": "Product updated successfully",
                "data": serializer.data,
                "status": True
            })
        except PermissionDenied as e:
            return Response({"message": str(e), "status": False}, status=403)
        except Exception as e:
            logger.exception(f"[VendorServiceUpdateAPIView] Error updating vendor Product: {str(e)}")
            return Response({
                "message": "An unexpected error occurred while updating the Product.",
                "error": str(e),
                "status": False
            }, status=500)


@method_decorator(name='get', decorator=swagger_auto_schema(tags=['Product Details']))       
class VendorServiceAllAPIView(generics.ListAPIView):
    serializer_class = VendorServiceSerializer
    permission_classes = [IsAuthenticated, IsVendor]

    def get_queryset(self):
        vendor = self.request.user

        try:
            # Get the Active status
            active_status = StatusMaster.objects.get(status_type__iexact='Active')
            
            # Only return services with Active status
            queryset = VendorService.objects.filter(vendor_id=vendor.id, status=active_status).order_by('id')

        except StatusMaster.DoesNotExist:
            # If Active status does not exist, return empty queryset
            logger.warning("[VendorServiceAllAPIView] 'Active' status not found. Returning empty list.")
            queryset = VendorService.objects.none()
        except Exception as e:
            logger.exception(f"[VendorServiceAllAPIView] Error fetching Product: {str(e)}")
            queryset = VendorService.objects.none()

        return queryset

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True)
            return Response({
                "message": "Active vendor Product fetched successfully",
                "data": serializer.data,
                "status": True
            })
        except Exception as e:
            logger.exception(f"[VendorServiceAllAPIView] Unexpected error: {str(e)}")
            return Response({
                "message": "An unexpected error occurred while fetching vendor Product.",
                "error": str(e),
                "status": False
            }, status=500)
        

@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['Product Details']))
class VendorServiceDeleteAPIView(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated, IsVendor]

    def get_object(self):
        vendor = self.request.user
        product_id = self.kwargs.get('product_id')

        if not product_id:
            raise PermissionDenied("Product ID is required.")

        try:
            service = VendorService.objects.get(vendor_id=vendor.id, id=product_id)
        except VendorService.DoesNotExist:
            raise PermissionDenied("product ID not found or you don't have permission to delete it.")

        return service

    def delete(self, request, *args, **kwargs):
        try:
            service = self.get_object()

            # Get Inactive status
            try:
                inactive_status = StatusMaster.objects.get(status_type__iexact='Inactive')
            except StatusMaster.DoesNotExist:
                return Response({
                    "message": "'Inactive' status not defined in the system.",
                    "status": False
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # Soft delete the service
            service.status = inactive_status
            service.save()

            return Response({
                "message": "Product deleted successfully",
                "status": True
            })

        except PermissionDenied as e:
            return Response({"message": str(e), "status": False}, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            logger.exception(f"[VendorServiceSoftDeleteAPIView] Error deleting Product: {str(e)}")
            return Response({
                "message": "An unexpected error occurred while deleting the Product.",
                "error": str(e),
                "status": False
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class VendorContactUpdateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        vendor = request.user 

        serializer = VendorContactUpdateSerializer(
            vendor,
            data=request.data,
            partial=True
        )

        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "Contact Information Updated Successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VendorDocumentListAPIView(APIView):
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        phone = request.user.contact_no

        docs = VendorDocument.objects.filter(
            vendor_business_no=phone,
            status="PERMANENT"
        )

        return Response({
            "status": True,
            "documents": VendorDocumentSerializer(docs, many=True).data
        })

class VendorDocumentDeleteAPIView(APIView):
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated,)

    def delete(self, request, doc_id):
        phone = request.user.contact_no

        doc = VendorDocument.objects.filter(
            id=doc_id,
            vendor_business_no=phone,
            status="PERMANENT"
        ).first()

        if not doc:
            return Response({"error": "Document not found"}, status=404)

        doc.status = "DELETED"
        doc.save()

        return Response({"message": "Document deleted successfully"})
class VendorDocumentUpdateAPIView(APIView):
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated,)

    def put(self, request, doc_id):
        phone = request.user.contact_no
        image = request.FILES.get("file")

        doc = VendorDocument.objects.filter(
            id=doc_id, vendor_business_no=phone, status="PERMANENT"
        ).first()

        if not doc:
            return Response({"error": "Document not found"}, status=404)

        s3 = boto3.client(
            "s3",
            aws_access_key_id=config("s3AccessKey"),
            aws_secret_access_key=config("s3Secret"),
        )
        bucket = config("S3_BUCKET_NAME")

        ext = os.path.splitext(image.name)[1]
        unique = f"{uuid.uuid4().hex}{ext}"
        key = f"vendor_documents/{phone}/{unique}"

        s3.upload_fileobj(image, bucket, key, ExtraArgs={"ACL": "public-read"})
        url = f"https://{bucket}.s3.amazonaws.com/{key}"

        doc.document_url = url
        doc.save()

        return Response({"message": "Document updated successfully"})

