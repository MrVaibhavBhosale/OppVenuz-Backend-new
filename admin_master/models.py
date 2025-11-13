from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

# Model For Role 
class Role_master(models.Model):

    role_name = models.CharField(max_length=255)
    status = models.IntegerField(default=1)

    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.role_name
    
# Model For Best Suited For
class Best_suited_for(models.Model):

    name = models.CharField(max_length=255)
    status = models.IntegerField(default=1)

    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

# Model For State
class State_master(models.Model):

    state_name = models.CharField(max_length=255)
    state_code = models.IntegerField()
    status = models.IntegerField(default=1)

    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.state_name

# Model For City
class City_master(models.Model):
    state = models.ForeignKey(
        State_master, 
        on_delete=models.CASCADE,        
        related_name='cities'           
    )
    city_name = models.CharField(max_length=255)
    pincode = models.IntegerField()
    status = models.IntegerField(default=1)

    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.city_name}, {self.state.state_name}"
    
# Model For Payment Type
class Payment_type(models.Model):

    payment_type = models.CharField(max_length=255)
    status = models.IntegerField(default=1)
    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.payment_type
    

class Service_master(models.Model):
    service_name = models.CharField(max_length=255)
    registration_charges = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)
    status = models.IntegerField(default=1)

    def __str__(self):
        return self.service_name

class document_type(models.Model):
    STATUS_CHOICES = (
        (1, 'Active'),
        (2, 'Inactive'),
        (3, 'Deleted'),
    )

    document_type = models.CharField(max_length=255)
    status = models.PositiveSmallIntegerField(choices=STATUS_CHOICES, default=1)

    created_by = models.CharField(max_length=255, blank=True, null=True)
    updated_by = models.CharField(max_length=255, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.document_type

# Model For Article Type
class Article_type(models.Model):
    article_type = models.CharField(max_length=255)
    status = models.IntegerField(default=1)
    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.article_type

# Model For Delivery Options
class Delivery_option(models.Model):

    delivery_option = models.CharField(max_length=255)
    status = models.IntegerField(default=1)
    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.delivery_option
    
# Model For Best Deal
class Best_deal(models.Model):

    deal_name = models.CharField(max_length=255)
    image = models.URLField(max_length=255)
    occasion = models.CharField(max_length=255)
    duration_of_deal = models.DateTimeField(max_length=255)
    status = models.IntegerField(default=1)
    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.deal_name

# Model For App Version
class App_version(models.Model):

    app_version = models.CharField(max_length=255) 
    is_force_update = models.BooleanField(default=False) 
    status = models.IntegerField(default=1)
    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.app_version, self.is_force_update
    
# ------------------ STATUS MASTER ------------------
class StatusMaster(models.Model):
    STATUS_TYPE_CHOICES = (
        ('Active', 'Active'),
        ('Inactive', 'Inactive'),
        ('Deleted', 'Deleted'),
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected'),
        ('Archived', 'Archived'),
        ('Draft', 'Draft'),
        ('Completed', 'Completed'),
        ('Expired', 'Expired'),
        ('Paid', 'Paid'),
        ('Unpaid', 'Unpaid'),
        ('Suspended', 'Suspended'),
    )

    status_type = models.CharField(
        max_length=50,
        choices=STATUS_TYPE_CHOICES,
        default='Active'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        db_table = 'admin_master_status_master'

    def __str__(self):
        return self.status_type


# ------------------ CAKE MASTER ------------------
class CakeMaster(models.Model):
    shape_name = models.CharField(max_length=100, default="Round")
    cake_type = models.CharField(max_length=100, default="Egg")
    flavor = models.CharField(max_length=100, default="Vanilla")
    status = models.ForeignKey(StatusMaster, on_delete=models.PROTECT, default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        db_table = 'admin_master_cake_master'

    def __str__(self):
        return f"{self.flavor} - {self.shape_name} ({self.cake_type})"


# ------------------ COMPANY TYPE MASTER ------------------
class CompanyTypeMaster(models.Model):
    company_type = models.CharField(max_length=150, unique=True)
    status = models.ForeignKey(StatusMaster, on_delete=models.PROTECT, default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        db_table = 'admin_master_company_type_master'

    def __str__(self):
        return self.company_type


# ------------------ VENUE TYPE MASTER ------------------
class VenueTypeMaster(models.Model):
    venue_type = models.CharField(max_length=150, unique=True)
    status = models.ForeignKey(StatusMaster, on_delete=models.PROTECT, default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        db_table = 'admin_master_venue_type_master'

    def __str__(self):
        return self.venue_type


# ------------------ OPPVENUZ CHOICE MASTER ------------------
class OppvenuzChoiceMaster(models.Model):
    choice_name = models.CharField(max_length=255, unique=True)
    minimum_comments_count = models.PositiveIntegerField(default=0)
    archived_comments_count = models.PositiveIntegerField(default=0)
    average_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    status = models.ForeignKey(StatusMaster, on_delete=models.PROTECT, default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        db_table = 'admin_master_oppvenuz_choice_master'

    def save(self, *args, **kwargs):
        if self.minimum_comments_count > 0:
            self.average_percentage = (self.archived_comments_count / self.minimum_comments_count) * 100
        else:
            self.average_percentage = 0
        super().save(*args, **kwargs)

    def __str__(self):
        return self.choice_name


# ------------------ GST MASTER ------------------
class GstMaster(models.Model):
    gst_percentage = models.PositiveIntegerField()
    status = models.ForeignKey(StatusMaster, on_delete=models.PROTECT, default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        db_table = 'admin_master_gst_master'

    def __str__(self):
        return f"{self.gst_percentage}%"


class OnboardingScreens(models.Model):
    TYPE_CHOICES = (
        (1, "GIF"),
        (2, "FLASH"),
    )

    STATUS_CHOICES = (
        (1, "Active"),
        (2, "Deleted"),
    )

    title = models.CharField(max_length=255)
    media = models.JSONField(null=True, blank=True) 
    type = models.IntegerField(choices=TYPE_CHOICES, default=2) 
    order = models.IntegerField(default=0)
    status = models.IntegerField(choices=STATUS_CHOICES, default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["type", "order"]

    def __str__(self):
        return f"{self.title} ({self.get_type_display()})"


class Social_media_master(models.Model):
    media_name = models.CharField(max_length=255, unique=True)
    media_image = models.URLField(max_length=300)
    status = models.ForeignKey(StatusMaster, on_delete=models.PROTECT, default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return self.media_name
    
class Terms_and_condition_master(models.Model):
    title = models.CharField(max_length=255)
    content = models.TextField()
    slug = models.CharField(max_length=255, unique=True, blank=True)
    status = models.ForeignKey(StatusMaster, on_delete=models.PROTECT, default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        verbose_name = "Terms and Condition"
        verbose_name_plural = "Terms and Conditions"
        ordering = ['-created_at']

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = ''.join(e for e in self.title.upper() if e.isalnum())
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.title}"
    
# Model For Oppvenuz ques ans master
class Oppvenuz_ques_ans_master(models.Model):

    question = models.CharField(max_length=2500)
    answer = models.CharField(max_length=2500)
    status = models.IntegerField(default=1)
    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.question    

# Model For Oppvenuz ques ans master
class Common_setting(models.Model):

    min_photo_upload = models.IntegerField()
    max_photo_upload = models.IntegerField()
    min_video_upload = models.IntegerField()
    max_video_upload = models.IntegerField()
    min_photo_size = models.IntegerField()
    max_photo_size = models.IntegerField()
    min_video_size = models.IntegerField()
    max_video_size = models.IntegerField()
    image_format = models.CharField(max_length=500)
    video_format = models.CharField(max_length=500)
    min_document_upload = models.IntegerField()
    max_document_upload = models.IntegerField()
    document_format = models.CharField(max_length=500)
    status = models.IntegerField(default=1)
    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if Common_setting.objects.exists() and not self.pk:
            # Update the existing one instead of creating new
            existing = Common_setting.objects.first()
            self.pk = existing.pk
        super(Common_setting, self).save(*args, **kwargs)
     
    def __str__(self):
        return "Common Settings"
    
class CompanyDocumentMapping(models.Model):
    company_type = models.ForeignKey(CompanyTypeMaster, on_delete=models.CASCADE, related_name='mapped_documents')
    document_type = models.ForeignKey(document_type, on_delete=models.CASCADE, related_name='mapped_companies')
    status = models.PositiveSmallIntegerField(default=1)  
    created_by = models.CharField(max_length=255, blank=True, null=True)
    updated_by = models.CharField(max_length=255, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'admin_master_company_document_mapping'
        unique_together = ('company_type', 'document_type')

    def __str__(self):
        return f"{self.company_type.company_type} → {self.document_type.document_type}"
