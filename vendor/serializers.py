from rest_framework import serializers
from .models import (
    Vendor, 
    Vendor_registration, 
    VendorDocument,
    PhoneVerification,
    EmailVerification,
    VenderBusinessDescription,
    VendorDevice,
    ReadyToSellItem,
    ProductAddition,
    VendorSocialMedia,
    VendorMedia,
    VendorService,
    CelebrityBanner,
    BestDealBanner,
    )
from django.contrib.auth import authenticate
import re
from django.db import models
import os
from django.db.models import Q
from admin_master.models import (
    CompanyTypeMaster,
    Best_suited_for
)


class VendorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor
        fields = "__all__"

class VendorBasicSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor
        fields = ["id", "business_name", "email", "contact_number", "working_since", "years_of_experience"]

class VendorDescriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor
        fields = ["id", "description"]


class LocationSerializer(serializers.Serializer):
    pincode = serializers.CharField(required=True)
    address = serializers.CharField(required=True)
    latitude = serializers.DecimalField(max_digits=13, decimal_places=6, required=True)
    longitude = serializers.DecimalField(max_digits=13, decimal_places=6, required=True)


class VendorDocumentSerializer(serializers.ModelSerializer):
    phone = serializers.CharField(source="verification.phone", read_only=True)
    company_type = serializers.CharField(source="company_type.company_type", read_only=True)
    class Meta:
        model = VendorDocument
        fields = ['id', 'phone', 'company_type', 'document_type', 'document_url', 'status']

class VendorSignupSerializer(serializers.ModelSerializer):
    location = LocationSerializer(write_only=True)
    mpin = serializers.CharField(write_only=True, required=True)
    date_of_birth = serializers.DateField(input_formats=['%Y-%m-%d', '%d-%m-%Y'])
    documents = VendorDocumentSerializer(many=True, required=False)
    best_suited = serializers.PrimaryKeyRelatedField(
        queryset=Best_suited_for.objects.all(),
        required=False,
        allow_null=True
    )

    class Meta:
        model = Vendor_registration
        fields = [
            'first_name', 'middle_name', 'last_name', 'email', 'contact_no', 'whatsapp_no',
            'gender', 'date_of_birth', 'mpin',
            'business_name', 'service_id', 'best_suited', 'city_id', 'state_id',
            'location', 'working_since', 'year_of_experience',
            'documents', 'payment_status','profile_status'
        ]
        extra_kwargs = {
            # 'terms_conditions': {'required': True},
            # 'privacy_policy': {'required': True},
            # 'payment_cancellation': {'required': True},
        }

    # ---------------- VALIDATIONS ----------------
    def validate_email(self, value):
        if value and not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', value):
            raise serializers.ValidationError("Invalid email format.")
        return value

    def validate_contact_no(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("Contact number must contain digits only.")
        if not 10 <= len(value) <= 12:
            raise serializers.ValidationError("Contact number must be between 10 and 12 digits.")
        return value

    def validate_whatsapp_no(self, value):
        if value and not value.isdigit():
            raise serializers.ValidationError("WhatsApp number must contain digits only.")
        if value and not 10 <= len(value) <= 12:
            raise serializers.ValidationError("WhatsApp number must be between 10 and 12 digits.")
        return value

    def validate_mpin(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("MPIN must contain only digits.")
        if len(value) != 6:
            raise serializers.ValidationError("MPIN must be 6 digits long.")
        return value

    def validate_year_of_experience(self, value):
        if value < 0:
            raise serializers.ValidationError("Year of experience cannot be negative.")
        return value

    def validate(self, attrs):
        email = attrs.get('email')
        contact_no = attrs.get('contact_no')
        service_id = attrs.get('service_id')

        if Vendor_registration.objects.filter(
            models.Q(email=email) | models.Q(contact_no=contact_no),
            service_id=service_id
        ).exists():
            raise serializers.ValidationError(
                "Vendor with this email or contact number is already registered for this service."
            )
        return attrs

    # ---------------- CREATE ----------------
    def create(self, validated_data):
        # Handle location (pincode, address, lat/lon)
        location = validated_data.pop('location', None)
        if location:
            validated_data['pincode'] = location.get('pincode')
            validated_data['address'] = location.get('address')
            validated_data['latitude'] = location.get('latitude')
            validated_data['longitude'] = location.get('longitude')

        # Handle documents (if provided)
        document_ids = validated_data.pop("documents", [])

        # Handle MPIN securely
        mpin = validated_data.pop('mpin')

        # Create vendor instance
        user = Vendor_registration(is_active=True, **validated_data)
        user.set_mpin(mpin)
        user.save()

        # ✅ Default image set (if not given)
        if not user.profile_image:
            user.profile_image = os.getenv('DEFAULT_VENDOR_IMAGE_PATH')
        user.save()

        uploaded_docs = VendorDocument.objects.filter(
            vendor_business_no=str(user.contact_no),
            status="TEMP"
        )

        if uploaded_docs.exists():
            document_ids = list(uploaded_docs.values_list("id", flat=True))
            user.document_id = document_ids
            user.save(update_fields=["document_id"])        

        user.refresh_from_db()
        return user

    # ---------------- RESPONSE ----------------
    def to_representation(self, instance):
        best_suited_name = None

        if instance.best_suited:
            best_suited_name = getattr(instance.best_suited, 'subcat_name', None) or getattr(instance.best_suited, 'name', None)

        return {
            "vendor_id": instance.vendor_id,
            "business_name": instance.business_name,
            "first_name": instance.first_name,
            "middle_name": instance.middle_name,
            "last_name": instance.last_name,
            "email": instance.email,
            "contact_no": instance.contact_no,
            "whatsapp_no": instance.whatsapp_no,
            "gender": instance.gender,
            "date_of_birth": instance.date_of_birth,
            "city": getattr(instance.city_id, 'city_name', None),
            "state": getattr(instance.state_id, 'state_name', None),
            "pincode": instance.pincode,
            "address": instance.address,
            "service_name": getattr(instance.service_id, 'service_name', None),
            "best_suited_for": best_suited_name,
            "working_since": instance.working_since,
            "year_of_experience": instance.year_of_experience,
            "referral_code": instance.referral_code,
            "document_id": instance.document_id,
            "payment_status": instance.payment_status,
            "profile_status": instance.profile_status,
            "created_at": instance.created_at.isoformat() if instance.created_at else None,
            "documents": VendorDocumentSerializer(
                VendorDocument.objects.filter(
                    vendor_business_no=instance.contact_no, status="PERMANENT"
                ),
                many=True
            ).data,
        }

    

class VendorLoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    mpin = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        username = attrs.get('username')
        mpin = attrs.get('mpin')

        user = authenticate(username=username, mpin=mpin)
        if not user:
            raise serializers.ValidationError("Invalid credentials")
        if not user.is_active:
            raise serializers.ValidationError("User account is disabled.")
        
        attrs['user'] = user
        return attrs
    

class VendorDataSerializer(serializers.ModelSerializer):
    mpin = serializers.CharField(write_only=True)
    documents = VendorDocumentSerializer(many=True, read_only=True)

    class Meta:
        model = Vendor_registration
        fields = '__all__'

    def to_representation(self, instance):
        return {
            "vendor_id": instance.vendor_id,
            "business_name": instance.business_name,
            "first_name": instance.first_name,
            "last_name": instance.last_name,
            "email": instance.email,
            "contact_no": instance.contact_no,
            "gender": instance.gender,
            "date_of_birth": instance.date_of_birth,
            "city": getattr(instance.city_id, 'city_name', None),
            "state": getattr(instance.state_id, 'state_name', None),
            "pincode": instance.pincode,
            "address": instance.address,
            "service_name": getattr(instance.service_id, 'service_name', None),
            "best_suited_for": getattr(instance.best_suited, 'subcat_name', None),
            "working_since": instance.working_since,
            "year_of_experience": instance.year_of_experience,
            "referral_code": instance.referral_code,
            "created_at": instance.created_at.isoformat() if instance.created_at else None,
            "payment_status": instance.payment_status,
            "profile_status": instance.profile_status,
            "profile_image": instance.profile_image,
            "documents": VendorDocumentSerializer(
                VendorDocument.objects.filter(
                    vendor_business_no=instance.contact_no, status="PERMANENT"
                ),
                many=True
            ).data,
        }


class RequestEmailOTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailVerification
        fields = ['email']
        extra_kwargs = {
            'email': {'validators': []}
        }

    def validate_email(self, value):
        if not value:
            raise serializers.ValidationError("Email is required.")
        return value
    
class RequestPhoneOTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = PhoneVerification
        fields = ['phone']
        extra_kwargs = {
            'phone': {'validators': []}
        }

    def validate_phone(self, value):
        if not value:
            raise serializers.ValidationError("Phone number is required.")
        if not value.isdigit():
            raise serializers.ValidationError("Phone number must contain only digits.")
        if len(value) < 10:
            raise serializers.ValidationError("Phone number must be at least 10 digits long.")
        return value

    
class VerifyEmailOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=10)

class VerifyPhoneOTPSerializer(serializers.Serializer):
    phone = serializers.CharField()
    otp = serializers.CharField(max_length=10)
   
class ForgotMPINRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    phone = serializers.CharField(required=False)

    def validate(self, data):
        email = data.get('email')
        phone = data.get('phone')

        if not email and not phone:
            raise serializers.ValidationError("Email or phone is required.")

        if email:
            verification = EmailVerification.objects.filter(email=email, is_verified=True).first()
            if not verification:
                raise serializers.ValidationError("Email not verified or not found.")

        elif phone:
            verification = PhoneVerification.objects.filter(phone=phone, is_verified=True).first()
            if not verification:
                raise serializers.ValidationError("Phone number not verified or not found.")

        return data

class ChangeMPINSerializer(serializers.ModelSerializer):
    new_mpin = serializers.CharField(write_only=True, required=True)
    email = serializers.EmailField(required=False)
    contact_no = serializers.CharField(required=False)

    class Meta:
        model = Vendor_registration
        fields = ['email', 'contact_no', 'new_mpin']

    def validate_new_mpin(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("MPIN must contain only digits.")
        if len(value) != 6:
            raise serializers.ValidationError("MPIN must be exactly 6 digits long.")
        return value

    def validate(self, attrs):
        email = attrs.get('email')
        contact_no = attrs.get('contact_no')

        if not email and not contact_no:
            raise serializers.ValidationError("Either email or contact_no required")
        
        if email and contact_no:
            raise serializers.ValidationError("Provide only one of email and contact_no, not both")
        
        try:
            if email:
                vendor = Vendor_registration.objects.get(email=email)
            else:
                vendor = Vendor_registration.objects.get(contact_no=contact_no)
        except Vendor_registration.DoesNotExist:
            raise serializers.ValidationError("No vendor found with this email or contact_no")
        
        attrs['vendor'] = vendor
        return attrs

    def save(self, **kwargs):
        vendor = self.validated_data["vendor"]
        new_mpin = self.validated_data["new_mpin"]
        vendor.set_mpin(new_mpin)
        vendor.save(update_fields=['mpin'])
        return vendor

class VenderBusinessDescriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = VenderBusinessDescription
        fields = ['id', 'vendor_reg_id', 'description']
        read_only_fields = ['vendor_reg_id']

class ReadyToSellItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReadyToSellItem
        fields = "__all__"

class ProductAdditionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductAddition
        fields = '__all__'

class VendorRegistrationSerializer(serializers.ModelSerializer):
    state_name = serializers.CharField(source='state_id.state_name', read_only=True)
    city_name = serializers.CharField(source='city_id.city_name', read_only=True)
    service_name = serializers.CharField(source='service_id.service_name', read_only=True)
    documents = serializers.SerializerMethodField()

    class Meta:
        model = Vendor_registration
        fields = [
            'id', 'vendor_id', 'business_name',
            'first_name', 'middle_name', 'last_name',
            'email', 'contact_no', 'whatsapp_no',
            'gender', 'date_of_birth',
            'state_id', 'state_name', 'city_id', 'city_name',
            'pincode', 'address', 'latitude', 'longitude',
            'service_id', 'service_name', 'best_suited',
            'working_since', 'year_of_experience',
            'is_active', 'created_at', 'updated_at',
            'documents'
        ]

    def get_documents(self, obj):
        try:
            docs = VendorDocument.objects.filter(vendor_business_no=obj.contact_no)
            return [
                {
                    "id": doc.id,
                    "document_type": doc.document_type,
                    "document_url": doc.document_url,
                    "status": doc.status,
                    "company_type": doc.company_type.company_type if doc.company_type else None,
                    "uploaded_at": doc.uploaded_at,
                    "expires_at": doc.expires_at,
               }
               for doc in docs
           ]
        except Exception as e:
            return []

class VendorBasicDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor_registration
        fields = [
            'first_name', 'middle_name', 'last_name',
            'business_name', 'gender', 'date_of_birth',
            'service_id', 'best_suited', 'year_of_experience'
        ]

class VendorSocialMediaSerializer(serializers.ModelSerializer):
    class Meta:
        model = VendorSocialMedia
        fields = '__all__'

class VendorMediaSerializer(serializers.ModelSerializer):
    class Meta:
        model = VendorMedia
        fields = "__all__"


class VendorServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = VendorService
        fields = '__all__'
        extra_kwargs = {
            'created_by': {'required': False},
            'updated_by': {'required': False},
            'vendor_id': {'required': False},  
        }

    def validate_data(self, value):
        if not isinstance(value, dict):
            raise serializers.ValidationError("Data must be a JSON object")
        return value

    def create(self, validated_data):
        # Automatically set vendor_id from request.user
        request = self.context.get('request')
        if request and hasattr(request.user, 'vendor_registration'):
            validated_data['vendor_id'] = request.user.vendor_registration
        elif request and isinstance(request.user, Vendor_registration):
            validated_data['vendor_id'] = request.user
        else:
            raise serializers.ValidationError("Vendor not found for this user.")

        validated_data['created_by'] = request.user.email if request.user else None
        validated_data['updated_by'] = request.user.email if request.user else None

        return super().create(validated_data)

class VendorContactUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor_registration
        fields = ['contact_no', 'whatsapp_no', 'email']
        extra_kwargs = {
            'contact_no': {'required': False},
            'whatsapp_no': {'required': False},
            'email': {'required': False},
        }

    def validate(self, attrs):
        instance = self.instance
        
        # Email unique validation
        if 'email' in attrs:
            email = attrs['email']
            if Vendor_registration.objects.exclude(pk=instance.pk).filter(email=email).exists():
                raise serializers.ValidationError({"email": "Email already exists."})

        # Contact unique validation
        if 'contact_no' in attrs:
            c_no = attrs['contact_no']
            if Vendor_registration.objects.exclude(pk=instance.pk).filter(contact_no=c_no).exists():
                raise serializers.ValidationError({"contact_no": "Contact number already exists."})

        # WhatsApp unique validation
        if 'whatsapp_no' in attrs:
            w_no = attrs['whatsapp_no']
            if Vendor_registration.objects.exclude(pk=instance.pk).filter(whatsapp_no=w_no).exists():
                raise serializers.ValidationError({"whatsapp_no": "WhatsApp number already exists."})

        return attrs

class CelebrityBannerSerializer(serializers.ModelSerializer):
    class Meta:
        model = CelebrityBanner
        fields = "__all__"

class BestDealBannerSerializer(serializers.ModelSerializer):
    class Meta:
        model = BestDealBanner
        fields = "__all__"
