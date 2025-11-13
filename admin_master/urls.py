from django.urls import path
from .views import (
    RoleCreateView,
    RoleListView,
    RoleUpdateView,
    RoleDeleteView,
    ServiceCreateView,
    ServiceListView,
    ServiceUpdateView,
    ServiceDeleteView,
    BestSuitedForCreateView,
    BestSuitedForListView,
    BestSuitedForUpdateView,
    BestSuitedForDeleteView,
    StateCreateView,
    StateListView,
    StateUpdateView,
    StateDeleteView,
    PaymentTypeCreateView,
    PaymentTypeListView,
    PaymentTypeUpdateView,
    PaymentTypeDeleteView,
    DocumentTypeCreateView,
    DocumentTypeListView,
    DocumentTypeUpdateView,
    DocumentTypeDeleteView, 
    CityCreateView,
    CityListView,
    CityUpdateView,
    CityDeleteView,
    ArticleTypeCreateView,
    ArticleTypeListView,
    ArticleTypeUpdateView,
    ArticleTypeDeleteView,
    DeliveryOptionCreateView,
    DeliveryOptionListView,
    DeliveryOptionUpdateView,
    DeliveryOptionDeleteView,
    BestDealCreateView,
    BestDealListView,
    BestDealUpdateView,
    BestDealDeleteView,
    AppVersionCreateView,
    AppVersionListView,
    AppVersionUpdateView,
    AppVersionDeleteView,
    BaseAPIView,
    CakeCreateView,
    CakeListView,
    CakeUpdateView,
    CakeDeleteView,
    CompanyTypeCreateView,
    CompanyTypeListView,
    CompanyTypeUpdateView,
    CompanyTypeDeleteView,
    VenueTypeListCreateView,
    VenueTypeUpdateView,
    VenueTypeDeleteView,
    OppvenuzChoiceCreateView,
    OppvenuzChoiceListView,
    OppvenuzChoiceUpdateView,
    OppvenuzChoiceDeleteView,
    GstMasterListView,
    GstMasterCreateView,
    GstMasterUpdateView,
    GstMasterDeleteView,
    GetOnboardingFlowView,
    UploadOnboardingView,
    SocialMediaUploadView,
    SocialMediaList,
    SocialMediaUpdateView,
    SocialMediaDeleteView,
    TermsAndConditionsView,
    TermsAndConditionsListView,
    TermsAndConditionsUpdateView,
    TermsAndConditionsDeleteView,
    QuestionAnswerCreateView,
    QuestionAnswerListView,
    QuestionAnswerUpdateView,
    QuestionAnswerDeleteView,
    CompanyDocumentMappingDeleteView,
    CompanyDocumentMappingListView,
    CompanyDocumentMappingCreateView,
)

urlpatterns = [
    # Role URLs
    path('createRole/', RoleCreateView.as_view(), name="create-role"),
    path('getAllRoles/', RoleListView.as_view(), name="get-role"),
    path('updateRole/<int:id>/', RoleUpdateView.as_view(), name="update-role"),
    path('deleteRole/<int:id>/', RoleDeleteView.as_view(), name="delete-role"),

    # Best Suited For URLs
    path('createBestSuitedFor/', BestSuitedForCreateView.as_view(), name="create-BestSuitedFor"),
    path('getAllBestSuitedFor/', BestSuitedForListView.as_view(), name="get-BestSuitedFor"),
    path('updateBestSuitedFor/<int:id>/', BestSuitedForUpdateView.as_view(), name="update-BestSuitedFor"),
    path('deleteBestSuitedFor/<int:id>/', BestSuitedForDeleteView.as_view(), name="delete-BestSuitedFor"),

    # State URLs
    path('createState/', StateCreateView.as_view(), name="create-State"),
    path('getAllState/', StateListView.as_view(), name="get-State"),
    path('updateState/<int:id>/', StateUpdateView.as_view(), name="update-State"),
    path('deleteState/<int:id>/', StateDeleteView.as_view(), name="delete-State"),

    # City URLs
    path('createCity/', CityCreateView.as_view(), name="create-City"),
    path('getAllCity/', CityListView.as_view(), name="get-City"),
    path('updateCity/<int:id>/', CityUpdateView.as_view(), name="update-City"),
    path('deleteCity/<int:id>/', CityDeleteView.as_view(), name="delete-City"),

    # Payment Types URLs
    path('createPaymentType/', PaymentTypeCreateView.as_view(), name="create-PaymentType"),
    path('getAllPaymentType/', PaymentTypeListView.as_view(), name="get-PaymentType"),
    path('updatePaymentType/<int:id>/', PaymentTypeUpdateView.as_view(), name="update-PaymentType"),
    path('deletePaymentType/<int:id>/', PaymentTypeDeleteView.as_view(), name="delete-PaymentType"),

    # Services URLs
    path('services/', ServiceCreateView.as_view(), name="servie-create"),
    path('getServices/', ServiceListView.as_view(), name="services-get"),
    path('updateservice/<int:id>/', ServiceUpdateView.as_view(), name="service-update"),
    path('deleteservice/<int:id>/', ServiceDeleteView.as_view(), name="delete-service"),

    # Document Type URLs
    path('createDocument/', DocumentTypeCreateView.as_view(), name='document-master-create'),
    path('getAllDocument/', DocumentTypeListView.as_view(), name='document-master-list'),
    path('updateDocument/<int:pk>/', DocumentTypeUpdateView.as_view(), name='document-master-update'),
    path('deleteDocument/<int:pk>/', DocumentTypeDeleteView.as_view(), name='document-master-delete'),

    # Article Types URLs
    path('createArticleType/', ArticleTypeCreateView.as_view(), name="create-ArticleType"),
    path('getAllArticleType/', ArticleTypeListView.as_view(), name="get-ArticleType"),
    path('updateArticleType/<int:id>/', ArticleTypeUpdateView.as_view(), name="update-ArticleType"),
    path('deleteArticleType/<int:id>/', ArticleTypeDeleteView.as_view(), name="delete-ArticleType"),

    # Delivery Option URLs
    path('createDeliveryOption/', DeliveryOptionCreateView.as_view(), name="create-DeliveryOption"),
    path('getAllDeliveryOption/', DeliveryOptionListView.as_view(), name="get-DeliveryOption"),
    path('updateDeliveryOption/<int:id>/', DeliveryOptionUpdateView.as_view(), name="update-DeliveryOption"),
    path('deleteDeliveryOption/<int:id>/', DeliveryOptionDeleteView.as_view(), name="delete-DeliveryOption"),

    # Best Deal URLs
    path('createBestDeal/', BestDealCreateView.as_view(), name="create-BestDeal"),
    path('getAllBestDeal/', BestDealListView.as_view(), name="get-BestDeal"),
    path('updateBestDeal/<int:id>/', BestDealUpdateView.as_view(), name="update-BestDeal"),
    path('deleteBestDeal/<int:id>/', BestDealDeleteView.as_view(), name="delete-BestDeal"),

    # App Version URLs
    path('createAppVersion/', AppVersionCreateView.as_view(), name="create-AppVersion"),
    path('getAllAppVersion/', AppVersionListView.as_view(), name="get-AppVersion"),
    path('updateAppVersion/<int:id>/', AppVersionUpdateView.as_view(), name="update-AppVersion"),
    path('deleteAppVersion/<int:id>/', AppVersionDeleteView.as_view(), name="delete-AppVersion"),

    # App Version URLs
    path('baseApi/', BaseAPIView.as_view(), name="get-baseApi"),

    #cakes (shape,flavor,type)
    path('cakes/', CakeCreateView.as_view(), name='cake-create'),     
    path('getcakes/', CakeListView.as_view(), name='cake-list'),  
    path('updatecakes/<int:id>/', CakeUpdateView.as_view(), name='cake-update'), 
    path('deletecakes/<int:id>/', CakeDeleteView.as_view(), name='cake-delete'), 

    #company-type
    path('company-types/', CompanyTypeCreateView.as_view(), name='company-type-create'),
    path('getcompany-types/', CompanyTypeListView.as_view(), name='company-type-list'),                             
    path('updatecompany-types/<int:id>/', CompanyTypeUpdateView.as_view(), name='company-type-update'),
    path('deletecompany-types/<int:id>/', CompanyTypeDeleteView.as_view(), name='company-type-delete'), 

    #venue-types
    path('venue-types/', VenueTypeListCreateView.as_view(), name='venue-type-list-create'),
    path('updatevenue-types/<int:id>/', VenueTypeUpdateView.as_view(), name='venue-type-update'),
    path('deletevenue-types/<int:id>/', VenueTypeDeleteView.as_view(), name='venue-type-delete'),

    path('choices/', OppvenuzChoiceListView.as_view(), name='choice-list'),         
    path('choices/<int:pk>/', OppvenuzChoiceListView.as_view(), name='choice-detail'),  
    path('choices/create/', OppvenuzChoiceCreateView.as_view(), name='choice-create'),  
    path('choices/update/<int:pk>/', OppvenuzChoiceUpdateView.as_view(), name='choice-update'),  
    path('choices/delete/<int:pk>/', OppvenuzChoiceDeleteView.as_view(), name='choice-delete'), 

    path('gst_master/', GstMasterListView.as_view(), name='gst-master-list'),
    path('gst_master/create/', GstMasterCreateView.as_view(), name='gst-master-create'),
    path('gst_master/update/<int:pk>/', GstMasterUpdateView.as_view(), name='gst-master-update'),
    path('gst_master/delete/<int:pk>/', GstMasterDeleteView.as_view(), name='gst-master-delete'),

    path('addsocialmedia/', SocialMediaUploadView.as_view(), name="add-social-media"),
    path('socialmedialist/', SocialMediaList.as_view(), name="get-social-media-list"),
    path('socialmediaupdate/<int:id>/', SocialMediaUpdateView.as_view(), name="update-social_media"),
    path('socialmediadelete/<int:id>/', SocialMediaDeleteView.as_view(), name='socialmedia-delete'),
    path('addtermsandconditions/',TermsAndConditionsView.as_view(), name='add-terms-and-conditions'),
    path('termsandconditionsList/',TermsAndConditionsListView.as_view(), name="get-terms-and-conditions"),
    path('termsandconditionupdate/<int:id>/', TermsAndConditionsUpdateView.as_view(), name="update-terms-and-conditions"),
    path("termsandconditiondelete/<int:id>/", TermsAndConditionsDeleteView.as_view(), name="terms-delete"),

    # App Version URLs
    path('createQuestionAnswer/', QuestionAnswerCreateView.as_view(), name="create-QuestionAnswer"),
    path('getAllQuestionAnswer/', QuestionAnswerListView.as_view(), name="get-QuestionAnswer"),
    path('updateQuestionAnswer/<int:id>/', QuestionAnswerUpdateView.as_view(), name="update-QuestionAnswer"),
    path('deleteQuestionAnswer/<int:id>/', QuestionAnswerDeleteView.as_view(), name="delete-QuestionAnswer"),


    path("v1/uploadOnboarding/", UploadOnboardingView.as_view(), name="upload-onboarding"),
    path("v1/getOnboardingFlow/", GetOnboardingFlowView.as_view(), name="get-onboarding-flow"),

    path('create-company-document-mapping/', CompanyDocumentMappingCreateView.as_view(), name='create-company-document-mapping'),
    path('get-company-document-mapping/', CompanyDocumentMappingListView.as_view(), name='get-company-document-mapping'),
    path('delete-company-document-mapping/<int:pk>/', CompanyDocumentMappingDeleteView.as_view(), name='delete-company-document-mapping'),

]

