from rest_framework import serializers
from rest_framework.serializers import ValidationError
from .models import (
Role_master, 
Service_master, 
Best_suited_for, 
State_master, 
Payment_type,
document_type,
City_master,
Article_type,
Delivery_option,
Best_deal,
App_version,
CakeMaster,
CompanyTypeMaster,
VenueTypeMaster,
StatusMaster,
OppvenuzChoiceMaster,
GstMaster,
OnboardingScreens,
Terms_and_condition_master,
Social_media_master,
Oppvenuz_ques_ans_master,
CompanyDocumentMapping,

)

 # Role serializers
class RoleMasterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role_master
        fields = '__all__'
        read_only_fields = ('created_at', 'created_by', 'updated_at', 'updated_by','status')

    def validate_role_name(self, value):
        if Role_master.objects.filter(role_name=value, status__in=[1,2]).exists():
            raise ValidationError("Role name already exists.")
        return value

 # Best suited for serializers
class BestSuitedForSerializer(serializers.ModelSerializer):
    class Meta:
        model = Best_suited_for
        fields = '__all__'
        read_only_fields = ('created_at', 'created_by', 'updated_at', 'updated_by','status')

    def validate_name(self, value):
        if Best_suited_for.objects.filter(name=value, status__in=[1,2]).exists():
            raise ValidationError("Name already exists.")
        return value

 # State serializers
class StateSerializer(serializers.ModelSerializer):
    class Meta:
        model = State_master
        fields = '__all__'
        read_only_fields = ('created_at', 'created_by', 'updated_at', 'updated_by','status')

    def validate_name(self, value):
        if State_master.objects.filter(state_name=value).exists():
            raise ValidationError("State already exists.")
        return value

 # City serializers
class CitySerializer(serializers.ModelSerializer):
    state = serializers.PrimaryKeyRelatedField(
        queryset=State_master.objects.all(),
        required=True,
        help_text="ID of the State this city belongs to."
    )

    state_name = serializers.CharField(source='state.state_name', read_only=True)
    class Meta:
        model = City_master
        fields = '__all__'
        read_only_fields = ('created_at', 'created_by', 'updated_at', 'updated_by','status')

    def validate_city_name(self, value):
        city_id = self.instance.id if self.instance else None
        if City_master.objects.filter(city_name__iexact=value).exclude(id=city_id).exists():
            raise ValidationError("City with this name already exists.")
        return value
    
 # Payment Type serializers
class PaymentTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment_type
        fields = '__all__'
        read_only_fields = ('created_at', 'created_by', 'updated_at', 'updated_by','status')

    def validate_name(self, value):
        if Payment_type.objects.filter(payment_type=value).exists():
            raise ValidationError("Payment Type already exists.")
        return value
    

class ServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service_master
        fields = '__all__'
        read_only_fields = ('created_at', 'created_by', 'updated_at', 'updated_by')

    def validate_service_name(self, value):
        value = value.strip()
        qs = Service_master.objects.filter(service_name__iexact=value, status__in=[1, 2])

        # Exclude current instance if updating
        instance = getattr(self, 'instance', None)
        if instance:
            qs = qs.exclude(id=instance.id)

        if qs.exists():
            raise ValidationError("Service name already exists among active/inactive services")
        return value

    def validate(self, data):
        registration_charges = data.get("registration_charges")
        if registration_charges is not None and registration_charges < 0:
            raise ValidationError({"registration_charges": "Registration charges cannot be negative"})
        return data

class SocialMediaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Social_media_master
        fields = '__all__'
        read_only_fields = ('created_at', 'created_by', 'updated_at', 'updated_by')

    def validate_media_name(self, value):
        value = value.strip()
        qs = Social_media_master.objects.filter(media_name__iexact=value, status__in=[1, 2])

        instance = getattr(self, 'instance', None)
        if instance:
            qs = qs.exclude(id=instance.id)

        if qs.exists():
            raise ValidationError("Media name already exists among active/inactive entries")
        return value

    def validate_media_image(self, value):
        if not value.lower().endswith(('.png', '.jpg', '.jpeg', '.svg', '.webp')):
            raise ValidationError("Only image URLs ending with .png, .jpg, .jpeg, .svg, or .webp are allowed.")
        return value
    
class TermsConditionSerializer(serializers.ModelSerializer):
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = Terms_and_condition_master
        fields = [
            'id', 'title', 'content', 'slug',
            'status', 'status_display',
            'created_at', 'updated_at',
            'created_by', 'updated_by'
        ]
        read_only_fields = ('created_at', 'created_by', 'updated_at', 'updated_by')

    def validate(self, data):
        title = data.get('title')
        status = data.get('status')

        if status == 1:
            existing = Terms_and_condition_master.objects.filter(title__iexact=title, status__in=[1, 2])
            if self.instance:
                existing = existing.exclude(id=self.instance.id)
            if existing.exists():
                raise serializers.ValidationError(
                    {"title": "Terms & Conditions with the same title already exists."}
                )

        return data

class document_typeSerializer(serializers.ModelSerializer):
    class Meta:
        model = document_type
        fields = ['id', 'document_type', 'status', 'created_by', 'updated_by', 'updated_at']
        read_only_fields = ['created_by', 'updated_by', 'updated_at']

 # Article Type serializers
class ArticleTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Article_type
        fields = '__all__'
        read_only_fields = ('created_at', 'created_by', 'updated_at', 'updated_by','status')

    def validate_name(self, value):
        if Article_type.objects.filter(article_type=value).exists():
            raise ValidationError("Article Type already exists.")
        return value

 # Delivery Option serializers
class DeliveryOptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Delivery_option
        fields = '__all__'
        read_only_fields = ('created_at', 'created_by', 'updated_at', 'updated_by','status')

    def validate_name(self, value):
        if Delivery_option.objects.filter(delivery_option=value).exists():
            raise ValidationError("Delivery Option already exists.")
        return value

 # Best Deal serializers
class BestDealSerializer(serializers.ModelSerializer):
    class Meta:
        model = Best_deal
        fields = '__all__'
        read_only_fields = ('created_at', 'created_by', 'updated_at', 'updated_by','status')

    def validate_name(self, value):
        if Best_deal.objects.filter(deal_name=value).exists():
            raise ValidationError("Deal Name already exists.")
        return value

 # Best Deal serializers
class AppVersionSerializer(serializers.ModelSerializer):
    class Meta:
        model = App_version
        fields = '__all__'
        read_only_fields = ('created_at', 'created_by', 'updated_at', 'updated_by','status')

    def validate_name(self, value):
        if App_version.objects.filter(app_version=value).exists():
            raise ValidationError("Version already exists.")
        return value
    
class StatusMasterSerializer(serializers.ModelSerializer):
    class Meta:
        model = StatusMaster
        fields = ['id', 'status_type']


# ------------------ Cake Master ------------------
class CakeMasterSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()

    class Meta:
        model = CakeMaster
        fields = ['id', 'shape_name', 'cake_type', 'flavor', 'status', 'created_at', 'updated_at']

    def get_status(self, obj):
        return obj.status.status_type if obj.status else None


# ------------------ Company Type Master ------------------
class CompanyTypeMasterSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()

    class Meta:
        model = CompanyTypeMaster
        fields = ['id', 'company_type', 'status', 'created_at', 'updated_at']

    def get_status(self, obj):
        return obj.status.status_type if obj.status else None


# ------------------ Venue Type Master ------------------
class VenueTypeMasterSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()

    class Meta:
        model = VenueTypeMaster
        fields = ['id', 'venue_type', 'status', 'created_at', 'updated_at']

    def get_status(self, obj):
        return obj.status.status_type if obj.status else None


# ------------------ Oppvenuz Choice Master ------------------
class OppvenuzChoiceMasterSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    average_percentage = serializers.SerializerMethodField()

    class Meta:
        model = OppvenuzChoiceMaster
        fields = ['id', 'choice_name', 'minimum_comments_count', 'archived_comments_count', 'average_percentage', 'status', 'created_at', 'updated_at']

    def get_status(self, obj):
        if hasattr(obj, 'status') and obj.status:
            return obj.status.status_type
        return "Active" if obj.status else "Inactive"

    def get_average_percentage(self, obj):
        return f"{obj.average_percentage:.0f}%"


# ------------------ GST Master ------------------
class GstMasterSerializer(serializers.ModelSerializer):
    gst_percentage = serializers.SerializerMethodField()
    gst_percentage_input = serializers.IntegerField(write_only=True)
    status = serializers.CharField(source='status.status_type', read_only=True)

    class Meta:
        model = GstMaster
        fields = ['id', 'gst_percentage', 'gst_percentage_input', 'status']

    def get_gst_percentage(self, obj):
        return f"{obj.gst_percentage}%"

    def validate_gst_percentage_input(self, value):
        if value < 0 or value > 100:
            raise serializers.ValidationError("GST percentage must be between 0 and 100.")
        return value

    def create(self, validated_data):
        value = validated_data.pop('gst_percentage_input')
        return GstMaster.objects.create(gst_percentage=value)

    def update(self, instance, validated_data):
        value = validated_data.pop('gst_percentage_input', None)
        if value is not None:
            instance.gst_percentage = value
            instance.save()
        return instance
    
 # Oppvenuz question answer for serializers
class  QuestionAnswerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Oppvenuz_ques_ans_master
        fields = '__all__'
        read_only_fields = ('created_at', 'created_by', 'updated_at', 'updated_by','status')

    def validate_name(self, value):
        if Oppvenuz_ques_ans_master.objects.filter(name=value, status__in=[1,2]).exists():
            raise ValidationError("Name already exists.")
        return value

class OnboardingScreenSerializer(serializers.ModelSerializer):
    class Meta:
        model = OnboardingScreens
        fields = "__all__"
        read_only_fields = ("created_at", "updated_at", "status")

class CompanyDocumentMappingSerializer(serializers.ModelSerializer):
    company_type_name = serializers.CharField(source='company_type.company_type', read_only=True)
    document_type_name = serializers.CharField(source='document_type.document_type', read_only=True)

    class Meta:
        model = CompanyDocumentMapping
        fields = ['id', 'company_type', 'company_type_name', 'document_type', 'document_type_name', 'status', 'created_by', 'updated_by', 'updated_at']
