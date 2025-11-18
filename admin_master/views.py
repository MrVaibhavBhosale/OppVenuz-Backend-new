from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import ValidationError
from django.utils import timezone
from drf_yasg.utils import swagger_auto_schema
from django.utils.decorators import method_decorator
import logging
from rest_framework.views import APIView
from drf_yasg import openapi
from .utils import get_status
from django.shortcuts import get_object_or_404
from rest_framework.parsers import MultiPartParser, FormParser
import boto3
from decouple import config

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
    StatusMaster,
    CakeMaster,
    CompanyTypeMaster,
    VenueTypeMaster,
    OppvenuzChoiceMaster,
    GstMaster,
    OnboardingScreens,
    Social_media_master,
    Terms_and_condition_master,
    Oppvenuz_ques_ans_master,
    CompanyDocumentMapping,
)
 
from .serializers import (
    RoleMasterSerializer, 
    ServiceSerializer, 
    BestSuitedForSerializer, 
    StateSerializer, 
    PaymentTypeSerializer,
    document_typeSerializer,
    CitySerializer,
    ArticleTypeSerializer,
    DeliveryOptionSerializer,
    BestDealSerializer,
    AppVersionSerializer,
    CakeMasterSerializer,
    CompanyTypeMasterSerializer,
    VenueTypeMasterSerializer,
    OppvenuzChoiceMasterSerializer,
    GstMasterSerializer,
    OnboardingScreenSerializer,
    SocialMediaSerializer,
    TermsConditionSerializer,
    QuestionAnswerSerializer,
    CompanyDocumentMappingSerializer,
    
)

logger = logging.getLogger("django")

# ------------------ ADMIN ROLES -----------------------------------
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['Admin Roles']))
class RoleCreateView(generics.CreateAPIView):    
    queryset = Role_master.objects.all()
    serializer_class = RoleMasterSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        user_fullname = getattr(self.request.user, 'fullname', self.request.user.username)
        role_name = serializer.validated_data.get('role_name')
        if Role_master.objects.filter(role_name__iexact=role_name, status__in=[1,2]).exists():
         raise ValidationError({"role_name": f"'{role_name}' already exists and is active."})

        if role_name and not role_name.replace(' ', '').isalpha():
            logger.warning(f"Invalid role name: {role_name}")
            raise ValidationError({"role_name": "Role name must contain only letters and spaces."})

        serializer.save(created_by=user_fullname, updated_by=user_fullname)

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        return Response({
            "status": True,
            "message": "Role created successfully",
            "data": response.data
        }, status=status.HTTP_201_CREATED)

@method_decorator(name='get', decorator=swagger_auto_schema(tags=['Admin Roles']))
class RoleListView(generics.ListAPIView):
    serializer_class = RoleMasterSerializer
    permission_classes = [AllowAny]
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = Role_master.objects.filter(status=1).order_by('-id')
        role = self.request.query_params.get('role_name', None)
        if role:
            queryset = queryset.filter(role_name__icontains=role)
            if not queryset.exists():
                logger.warning(f"{role} no such role exists")
                raise ValidationError({"role_name": f"{role} no such role exists"})
        return queryset
    def list(self, request, *args, **kwargs):
        serializer = self.get_serializer(self.get_queryset(), many=True)
        return Response({"status": True, "message": "Roles fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)


@method_decorator(name='put', decorator=swagger_auto_schema(tags=['Admin Roles']))
@method_decorator(name='patch', decorator=swagger_auto_schema(tags=['Admin Roles']))
class RoleUpdateView(generics.UpdateAPIView):
    queryset = Role_master.objects.filter(status=1)
    serializer_class = RoleMasterSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def perform_update(self, serializer):
        user = self.request.user
        data = serializer.validated_data
        role_name = data.get('role_name', None)

        if role_name and not role_name.replace(' ', '').isalpha():
            logger.warning(f"Invalid role name: {role_name}")
            raise ValidationError({"role_name": "Role name must contain only letters and spaces."})

        updated_by = getattr(user, "fullname", user.username)
        serializer.save(updated_by=updated_by)
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"status": True, "message": "Role updated successfully", "data": response.data}, status=status.HTTP_200_OK)


@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['Admin Roles']))
class RoleDeleteView(generics.DestroyAPIView):
    queryset = Role_master.objects.filter(status=1)
    serializer_class = RoleMasterSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            user = request.user
            instance.status = 3
            instance.updated_by = getattr(user, "fullname", user.username)
            instance.updated_at = timezone.now()
            instance.save(update_fields=['status', 'updated_by', 'updated_at'])
            return Response({"status": True,"message": "Role deleted successfully."},status=status.HTTP_200_OK)
        except Role_master.DoesNotExist:
            logger.warning(f"Role ID {kwargs.get('id')} not found")
            return Response({"error": "Role not found"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error deleting role: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ----------------------- ADMIN BEST SUITED FOR -----------------------------------
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['Admin Best Suited For']))
class BestSuitedForCreateView(generics.CreateAPIView):
    queryset = Best_suited_for.objects.all()
    serializer_class = BestSuitedForSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        user = self.request.user
        data = serializer.validated_data
        name = data.get('name', None) 
        if name and not name.replace(' ', '').isalpha():
            raise ValidationError({"name": "Name must contain only letters and spaces."})
            
        user_fullname = getattr(self.request.user, 'fullname', self.request.user.username)
        best_suited = serializer.validated_data.get('name')
        if Best_suited_for.objects.filter(name__iexact=best_suited, status__in=[1,2]).exists():
         raise ValidationError({"name": f"'{name}' already exists and is active."})
        serializer.save(created_by=user_fullname, updated_by=user_fullname)
    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        return Response({"status": True, "message": "Best Suited created successfully", "data": response.data}, status=status.HTTP_201_CREATED)


@method_decorator(name='get', decorator=swagger_auto_schema(tags=['Admin Best Suited For']))
class BestSuitedForListView(generics.ListAPIView):
    serializer_class = BestSuitedForSerializer
    permission_classes = [AllowAny]
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = Best_suited_for.objects.filter(status=1).order_by('-id')
        name = self.request.query_params.get('name', None)
        if name:
            queryset = queryset.filter(name__icontains=name)
            if not queryset.exists():
                logger.warning(f"{name} no such name exists")
                raise ValidationError({"name": f"{name} no such name exists"})
        return queryset
    def list(self, request, *args, **kwargs):
        serializer = self.get_serializer(self.get_queryset(), many=True)
        return Response({"status": True, "message": "Best Suited fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)


@method_decorator(name='put', decorator=swagger_auto_schema(tags=['Admin Best Suited For']))
@method_decorator(name='patch', decorator=swagger_auto_schema(tags=['Admin Best Suited For']))
class BestSuitedForUpdateView(generics.UpdateAPIView):
    queryset = Best_suited_for.objects.filter(status=1)
    serializer_class = BestSuitedForSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def perform_update(self, serializer):
        user = self.request.user
        data = serializer.validated_data
        name = data.get('name', None)

        if name and not name.replace(' ', '').isalpha():
            logger.warning(f"Invalid name: {name}")
            raise ValidationError({"name": "Name must contain only letters and spaces."})

        updated_by = getattr(user, "fullname", user.username)
        serializer.save(updated_by=updated_by)
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"status": True, "message": "Best Suited updated successfully", "data": response.data}, status=status.HTTP_200_OK)


@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['Admin Best Suited For']))
class BestSuitedForDeleteView(generics.DestroyAPIView):
    queryset = Best_suited_for.objects.filter(status=1)
    serializer_class = BestSuitedForSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            user = request.user
            instance.status = 3
            instance.updated_by = getattr(user, "fullname", user.username)
            instance.updated_at = timezone.now()
            instance.save(update_fields=['status', 'updated_by', 'updated_at'])
            return Response({"status": True,"message": "Name deleted successfully."},status=status.HTTP_200_OK)
        except Best_suited_for.DoesNotExist:
            logger.warning(f"Name ID {kwargs.get('id')} not found")
            return Response({"error": "Name not found"}, status=404)
        except Exception as e:
            logger.error(f"Error deleting Name: {str(e)}")
            return Response({"error": str(e)}, status=500)

#  ---------------------- ADMIN STATE ---------------------------
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['Admin State']))
class StateCreateView(generics.CreateAPIView):
    queryset = State_master.objects.all()
    serializer_class = StateSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        data = serializer.validated_data
        state_name = data.get('state_name', None) 
        if state_name and not state_name.replace(' ', '').isalpha():
            raise ValidationError({"state_name": "State Name must contain only letters and spaces."})
            
        user_fullname = getattr(self.request.user, 'fullname', self.request.user.username)
        state = serializer.validated_data.get('state_name')
        if State_master.objects.filter(state_name__iexact=state, status__in=[1,2]).exists():
         raise ValidationError({"state": f"'{state}' already exists and is active."})
        serializer.save(created_by=user_fullname, updated_by=user_fullname)
    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        return Response({"status": True, "message": "State created successfully", "data": response.data}, status=status.HTTP_201_CREATED)


@method_decorator(name='get', decorator=swagger_auto_schema(tags=['Admin State']))
class StateListView(generics.ListAPIView):
    serializer_class = StateSerializer
    permission_classes = [AllowAny]
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = State_master.objects.filter(status=1).order_by('-id')
        state_name = self.request.query_params.get('state_name', None)
        if state_name:
            queryset = queryset.filter(state_name__icontains=state_name)
            if not queryset.exists():
                logger.warning(f"{state_name} no such State exists")
                raise ValidationError({"state_name": f"{state_name} no such name exists"})
        return queryset
    def list(self, request, *args, **kwargs):
        serializer = self.get_serializer(self.get_queryset(), many=True)
        return Response({"status": True, "message": "State fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)


@method_decorator(name='put', decorator=swagger_auto_schema(tags=['Admin State']))
@method_decorator(name='patch', decorator=swagger_auto_schema(tags=['Admin State']))
class StateUpdateView(generics.UpdateAPIView):
    queryset = State_master.objects.filter(status=1)
    serializer_class = StateSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def perform_update(self, serializer):
        user = self.request.user
        data = serializer.validated_data
        state_name = data.get('state_name', None)

        if state_name and not state_name.replace(' ', '').isalpha():
            logger.warning(f"Invalid state name: {state_name}")
            raise ValidationError({"state_name": "State Name must contain only letters and spaces."})

        updated_by = getattr(user, "fullname", user.username)
        serializer.save(updated_by=updated_by)
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"status": True, "message": "State updated successfully", "data": response.data}, status=status.HTTP_200_OK)


@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['Admin State']))
class StateDeleteView(generics.DestroyAPIView):
    queryset = State_master.objects.filter(status=1)
    serializer_class = StateSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            #  Check if any city is linked to this state
            if City_master.objects.filter(state=instance, status=1).exists():
                return Response(
                    {"error": "Cannot delete this state because it is linked with one or more cities."},
                    status=400
                )
            user = request.user
            instance.status = 3
            instance.updated_by = getattr(user, "fullname", user.username)
            instance.updated_at = timezone.now()
            instance.save(update_fields=['status', 'updated_by', 'updated_at'])
            return Response({"status": True,"message": "State deleted successfully."},status=status.HTTP_200_OK)
        except State_master.DoesNotExist:
            logger.warning(f"State ID {kwargs.get('id')} not found")
            return Response({"error": "State not found"}, status=404)
        except Exception as e:
            logger.error(f"Error deleting State: {str(e)}")
            return Response({"error": str(e)}, status=500)

#  ----------------------- ADMIN CITY ----------------------------------
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['Admin City']))
class CityCreateView(generics.CreateAPIView):
    queryset = City_master.objects.all()
    serializer_class = CitySerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        data = serializer.validated_data
        city_name = data.get('city_name', None) 
        if city_name and not city_name.replace(' ', '').isalpha():
            raise ValidationError({"city_name": "City Name must contain only letters and spaces."})
            
        user_fullname = getattr(self.request.user, 'fullname', self.request.user.username)
        city = serializer.validated_data.get('city_name')
        if City_master.objects.filter(city_name__iexact=city, status__in=[1,2]).exists():
         raise ValidationError({"city_name": f"'{city_name}' already exists and is active."})
        serializer.save(created_by=user_fullname, updated_by=user_fullname)
    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        return Response({"status": True, "message": "City created successfully", "data": response.data}, status=status.HTTP_201_CREATED)


city_list_parameters = [
    openapi.Parameter(
        'state_id', 
        in_=openapi.IN_QUERY, # Specifies that the parameter is passed in the URL query string
        type=openapi.TYPE_INTEGER, 
        required=True,       # Marks it as required in the Swagger UI
        description='State ID used to filter the cities.'
    ),
    openapi.Parameter(
        'city_name', 
        in_=openapi.IN_QUERY, 
        type=openapi.TYPE_STRING, 
        required=False, 
        description='Optional. Search query to filter cities by name (case-insensitive).'
    ),
]

@method_decorator(name='get', decorator=swagger_auto_schema(tags=['Admin City'], manual_parameters=city_list_parameters 
))

class CityListView(generics.ListAPIView):
    serializer_class = CitySerializer
    permission_classes = [AllowAny]
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = City_master.objects.filter(status=1).order_by('-id')
        state_id = self.request.query_params.get('state_id', None)
        if state_id:
            queryset = queryset.filter(state_id=state_id)
            if not queryset.exists():
                logger.warning(f"No cities found for state_id={state_id}")
                raise ValidationError({"state_id": f"No cities found for this state_id ({state_id})"})
        else:
            raise ValidationError({"state_id": "state_id is required"})

        city_name = self.request.query_params.get('city_name', None)
        if city_name:
            queryset = queryset.filter(city_name__icontains=city_name)
            if not queryset.exists():
                logger.warning(f"{city_name} no such City exists in state_id={state_id}")
                raise ValidationError({"city_name": f"{city_name} no such city exists in this state"})
        return queryset
    def list(self, request, *args, **kwargs):
        serializer = self.get_serializer(self.get_queryset(), many=True)
        return Response({"status": True, "message": "Cities fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)


@method_decorator(name='put', decorator=swagger_auto_schema(tags=['Admin City']))
@method_decorator(name='patch', decorator=swagger_auto_schema(tags=['Admin City']))
class CityUpdateView(generics.UpdateAPIView):
    queryset = City_master.objects.filter(status=1)
    serializer_class = CitySerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def perform_update(self, serializer):
        user = self.request.user
        data = serializer.validated_data
        city_name = data.get('city_name', None)

        if city_name and not city_name.replace(' ', '').isalpha():
            logger.warning(f"Invalid city name: {city_name}")
            raise ValidationError({"city_name": "City Name must contain only letters and spaces."})

        updated_by = getattr(user, "fullname", user.username)
        serializer.save(updated_by=updated_by)
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"status": True, "message": "City updated successfully", "data": response.data}, status=status.HTTP_200_OK)


@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['Admin City']))
class CityDeleteView(generics.DestroyAPIView):
    queryset = City_master.objects.filter(status=1)
    serializer_class = CitySerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            user = request.user
            instance.status = 3
            instance.updated_by = getattr(user, "fullname", user.username)
            instance.updated_at = timezone.now()
            instance.save(update_fields=['status', 'updated_by', 'updated_at'])
            return Response({"status": True,"message": "City deleted successfully."},status=status.HTTP_200_OK)
        except City_master.DoesNotExist:
            logger.warning(f"City ID {kwargs.get('id')} not found")
            return Response({"error": "City not found"}, status=404)
        except Exception as e:
            logger.error(f"Error deleting City: {str(e)}")
            return Response({"error": str(e)}, status=500)


# ------------------- ADMIN PAYMENT TYPE ---------------------------
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['Admin Payment Types']))
class PaymentTypeCreateView(generics.CreateAPIView):
    queryset = Payment_type.objects.all()
    serializer_class = PaymentTypeSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        data = serializer.validated_data
        payment_type = data.get('payment_type', None) 
        if payment_type and not payment_type.replace(' ', '').isalpha():
            raise ValidationError({"payment_type": "Payment Type must contain only letters and spaces."})
            
        user_fullname = getattr(self.request.user, 'fullname', self.request.user.username)
        payment_type = serializer.validated_data.get('payment_type')
        if Payment_type.objects.filter(payment_type__iexact=payment_type, status__in=[1,2]).exists():
         raise ValidationError({"payment_type": f"'{payment_type}' already exists and is active."})
        serializer.save(created_by=user_fullname, updated_by=user_fullname)
    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        return Response({"status": True, "message": "Payment Type created successfully", "data": response.data}, status=status.HTTP_201_CREATED)


@method_decorator(name='get', decorator=swagger_auto_schema(tags=['Admin Payment Types']))
class PaymentTypeListView(generics.ListAPIView):
    serializer_class = PaymentTypeSerializer
    permission_classes = [AllowAny]
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = Payment_type.objects.filter(status=1).order_by('-id')
        payment_type = self.request.query_params.get('payment_type', None)
        if payment_type:
            queryset = queryset.filter(payment_type__icontains=payment_type)
            if not queryset.exists():
                logger.warning(f"{payment_type} no such payment type exists")
                raise ValidationError({"payment_type": f"{payment_type} no such payment type exists"})
        return queryset
    def list(self, request, *args, **kwargs):
        serializer = self.get_serializer(self.get_queryset(), many=True)
        return Response({"status": True, "message": "Payment Types fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)


@method_decorator(name='put', decorator=swagger_auto_schema(tags=['Admin Payment Types']))
@method_decorator(name='patch', decorator=swagger_auto_schema(tags=['Admin Payment Types']))
class PaymentTypeUpdateView(generics.UpdateAPIView):
    queryset = Payment_type.objects.filter(status=1)
    serializer_class = PaymentTypeSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def perform_update(self, serializer):
        user = self.request.user
        data = serializer.validated_data
        payment_type = data.get('payment_type', None)

        if payment_type and not payment_type.replace(' ', '').isalpha():
            logger.warning(f"Invalid payment type: {payment_type}")
            raise ValidationError({"payment_type": "payment type must contain only letters and spaces."})

        updated_by = getattr(user, "fullname", user.username)
        serializer.save(updated_by=updated_by)
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"status": True, "message": "Payment Type updated successfully", "data": response.data}, status=status.HTTP_200_OK)


@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['Admin Payment Types']))
class PaymentTypeDeleteView(generics.DestroyAPIView):
    queryset = Payment_type.objects.filter(status=1)
    serializer_class = PaymentTypeSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            user = request.user
            instance.status = 3
            instance.updated_by = getattr(user, "fullname", user.username)
            instance.updated_at = timezone.now()
            instance.save(update_fields=['status', 'updated_by', 'updated_at'])
            return Response({"status": True,"message": "Payment Type deleted successfully."},status=status.HTTP_200_OK)
        except Payment_type.DoesNotExist:
            logger.warning(f"Payment type ID {kwargs.get('id')} not found")
            return Response({"error": "payment type not found"}, status=404)
        except Exception as e:
            logger.error(f"Error deleting Payment type: {str(e)}")
            return Response({"error": str(e)}, status=500)

# -------------- ADMIN SERVICES ----------------------
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['Admin Services']))
class ServiceCreateView(generics.CreateAPIView):
    queryset = Service_master.objects.all()
    serializer_class = ServiceSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        user_fullname = getattr(self.request.user, 'fullname', self.request.user.username)
        serializer.save(
            created_by=user_fullname,
            updated_by=user_fullname
        )

    def create(self, request, *args, **kwargs):
        service_name = request.data.get("service_name", "").strip()

        if not service_name:
            return Response(
                {"message": "Service name cannot be empty.", "status": False},
                status=status.HTTP_400_BAD_REQUEST
            )

        existing_service = Service_master.objects.filter(
            service_name__iexact=service_name
        ).exclude(status=3).first()

        if existing_service:
            return Response(
                {
                    "message": f"Service '{service_name}' already exists.",
                    "status": False
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        return Response(
            {
                "message": "Service created successfully.",
                "data": serializer.data,
                "status": True
            },
            status=status.HTTP_201_CREATED
        )
    

@method_decorator(name='get', decorator=swagger_auto_schema(tags=['Admin Services']))
class ServiceListView(generics.ListAPIView):
    serializer_class = ServiceSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        queryset = Service_master.objects.filter(status__in=[1, 2])

        service = self.request.query_params.get('service_name', None)
        if service:
            queryset = queryset.filter(service_name__icontains=service.strip())
            if not queryset.exists():
                logger.warning(f"{service} — no such service exists.")
                raise ValidationError({"service_name": f"'{service}' does not exist."})
        return queryset
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)

        if queryset.exists():
            return Response(
                {
                    "message": "Service list fetched successfully.",
                    "count": queryset.count(),
                    "data": serializer.data,
                    "status": True
                },
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {
                    "message": "No services found.",
                    "data": [],
                    "status": False
                },
                status=status.HTTP_404_NOT_FOUND
            )
    


@method_decorator(name='put', decorator=swagger_auto_schema(tags=['Admin Services']))
@method_decorator(name='patch', decorator=swagger_auto_schema(tags=['Admin Services']))
class ServiceUpdateView(generics.UpdateAPIView):
    queryset = Service_master.objects.filter(status__in=[1, 2])
    serializer_class = ServiceSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def perform_update(self, serializer):
        user = self.request.user
        data = serializer.validated_data
        service_name = data.get('service_name', None)

        if service_name and not service_name.replace(' ', '').isalpha():
            logger.warning(f"invalid service name {service_name}")
            raise ValidationError({"service_name": "Service name must contains only letters and spaces."})
        
        if service_name:
            existing = Service_master.objects.filter(
                service_name__iexact=service_name.strip(),
                status__in=[1, 2]
            ).exclude(id=serializer.instance.id)
            if existing.exists():
                raise ValidationError({"service_name": f"A service with the name '{service_name}' already exists."})
        
        registration_charges = data.get('registration_charges', None)
        if registration_charges is not None and registration_charges < 0:
            logger.warning("invalid registration charges")
            raise ValidationError({"registration_charges": "Registration charges must contain positive number."})
        
        updated_by = getattr(user, "fullname", user.username)
        serializer.save(updated_by=updated_by)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)

        try:
            instance = self.get_object()
        except Service_master.DoesNotExist:
            return Response(
                {
                    "message": "Service not found.",
                    "status": False
                },
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        return Response(
            {
                "message": "Service updated successfully.",
                "data": serializer.data,
                "status": True
            },
            status=status.HTTP_200_OK
        )        


@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['Admin Services']))
class ServiceDeleteView(generics.DestroyAPIView):
    queryset = Service_master.objects.filter(status__in=[1, 2]) 
    serializer_class = ServiceSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def destroy(self, request, *args, **kwargs):
        service_id = kwargs.get('id')
        try:
            instance = self.get_object()
            instance.status = 3
            instance.updated_by = getattr(request.user, 'fullname', request.user.username)
            instance.save(update_fields=['status', 'updated_by', 'updated_at'])
            return Response(
                {
                    "message": "Service deleted successfully.",
                },
                status=status.HTTP_200_OK
            )

        except Service_master.DoesNotExist:
            logger.warning(f"Service ID {service_id} not found.")
            return Response(
                {
                    "message": "Service not found.",
                },
                status=status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            logger.error(f"Error deleting service ID {service_id}: {str(e)}")
            return Response(
                {
                    "message": "An unexpected error occurred while deleting the service.",
                    "error": str(e),
                    "status": False
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['Document Services']))
class DocumentTypeCreateView(generics.CreateAPIView):
    queryset = document_type.objects.all()
    serializer_class = document_typeSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        user_fullname = getattr(self.request.user, 'fullname', self.request.user.username)
        serializer.save(created_by=user_fullname, updated_by=user_fullname)
        document_type = serializer.validated_data.get('document_type')
        if document_type.objects.filter(document_type__iexact=document_type, status__in=[1,2]).exists():
         raise ValidationError({"document_type": f"'{document_type}' already exists and is active."})
        logger.info(f"Document created by user {user_fullname} with data: {self.request.data}")
    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        return Response({"status": True, "message": "Document Type created successfully", "data": response.data}, status=status.HTTP_201_CREATED)

@method_decorator(name='get', decorator=swagger_auto_schema(tags=['Document Services']))
class DocumentTypeListView(generics.ListAPIView):
    serializer_class = document_typeSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        queryset = document_type.objects.filter(status=1)
        doc_type = self.request.query_params.get('document_type', None)
        if doc_type:
            queryset = queryset.filter(document_type__icontains=doc_type)
            if not queryset.exists():
                logger.warning(f"{doc_type} no such document type exists")
                raise ValidationError({"document_type": f"{doc_type} no such document type exists"})
        logger.info(f"Document list fetched by user {self.request.user}")
        return queryset
    def list(self, request, *args, **kwargs):
        serializer = self.get_serializer(self.get_queryset(), many=True)
        return Response({"status": True, "message": "Document Types fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)

@method_decorator(name='put', decorator=swagger_auto_schema(tags=['Document Services']))
@method_decorator(name='patch', decorator=swagger_auto_schema(tags=['Document Services']))
class DocumentTypeUpdateView(generics.UpdateAPIView):
    queryset = document_type.objects.filter(status=1)
    serializer_class = document_typeSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

    def perform_update(self, serializer):
        user = self.request.user
        data = serializer.validated_data

        doc_type_name = data.get('document_type', None)
        if doc_type_name and not doc_type_name.replace(' ', '').isalpha():
            logger.warning(f"Invalid document_type name: {doc_type_name}")
            raise ValidationError({"document_type": "Document type must contain only letters and spaces."})

        updated_by = getattr(user, "fullname", user.username)
        serializer.save(updated_by=updated_by)
        logger.info(f"Document ID {self.get_object().id} updated by user {updated_by}")
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"status": True, "message": "Document Types updated successfully", "data": response.data}, status=status.HTTP_200_OK)

@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['Document Services']))
class DocumentTypeDeleteView(generics.DestroyAPIView):
    queryset = document_type.objects.filter(status=1)
    serializer_class = document_typeSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            user = request.user
            instance.status = 3  
            instance.updated_by = getattr(user, "fullname", user.username)
            instance.updated_at = timezone.now()
            instance.save(update_fields=['status', 'updated_by', 'updated_at'])
            logger.info(f"Document ID {instance.id} soft deleted by user {user}")
            return Response({"status": True,"message": "Document deleted successfully."},status=status.HTTP_200_OK)
        except document_type.DoesNotExist:
            logger.warning(f"Document ID {kwargs.get('pk')} not found for delete")
            return Response({"error": "Document not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error deleting document: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#  ----------------------- ADMIN ARTICLE TYPE ----------------------
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['Admin Article Types']))
class ArticleTypeCreateView(generics.CreateAPIView):
    queryset = Article_type.objects.filter(status=1)
    serializer_class = ArticleTypeSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        data = serializer.validated_data
        article_type = data.get('article_type', None) 
        if article_type and not article_type.replace(' ', '').isalpha():
            raise ValidationError({"article_type": "Article Type must contain only letters and spaces."})
            
        user_fullname = getattr(self.request.user, 'fullname', self.request.user.username)
        article_type = serializer.validated_data.get('article_type')
        if Article_type.objects.filter(article_type__iexact=article_type, status__in=[1,2]).exists():
         raise ValidationError({"article_type": f"'{article_type}' already exists and is active."})
        serializer.save(created_by=user_fullname, updated_by=user_fullname)
    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        return Response({"status": True, "message": "Article type created successfully", "data": response.data}, status=status.HTTP_201_CREATED)


@method_decorator(name='get', decorator=swagger_auto_schema(tags=['Admin Article Types']))
class ArticleTypeListView(generics.ListAPIView):
    serializer_class = ArticleTypeSerializer
    permission_classes = [AllowAny]
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = Article_type.objects.filter(status=1).order_by('-id')
        article_type = self.request.query_params.get('article_type', None)
        if article_type:
            queryset = queryset.filter(article_type__icontains=article_type)
            if not queryset.exists():
                logger.warning(f"{article_type} no such article type exists")
                raise ValidationError({"article_type": f"{article_type} no such article type exists"})
        return queryset
    def list(self, request, *args, **kwargs):
        serializer = self.get_serializer(self.get_queryset(), many=True)
        return Response({"status": True, "message": "Article Types fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)


@method_decorator(name='put', decorator=swagger_auto_schema(tags=['Admin Article Types']))
@method_decorator(name='patch', decorator=swagger_auto_schema(tags=['Admin Article Types']))
class ArticleTypeUpdateView(generics.UpdateAPIView):
    queryset = Article_type.objects.filter(status=1)
    serializer_class = ArticleTypeSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def perform_update(self, serializer):
        user = self.request.user
        data = serializer.validated_data
        article_type = data.get('article_type', None)

        if article_type and not article_type.replace(' ', '').isalpha():
            logger.warning(f"Invalid article type: {article_type}")
            raise ValidationError({"article_type": "article type must contain only letters and spaces."})

        updated_by = getattr(user, "fullname", user.username)
        serializer.save(updated_by=updated_by)
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"status": True, "message": "Article Types updated successfully", "data": response.data}, status=status.HTTP_200_OK)


@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['Admin Article Types']))
class ArticleTypeDeleteView(generics.DestroyAPIView):
    queryset = Article_type.objects.filter(status=1)
    serializer_class = ArticleTypeSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            user = request.user
            instance.status = 3
            instance.updated_by = getattr(user, "fullname", user.username)
            instance.updated_at = timezone.now()
            instance.save(update_fields=['status', 'updated_by', 'updated_at'])
            return Response({"status": True,"message": "Article Type deleted successfully."},status=status.HTTP_200_OK)
        except Article_type.DoesNotExist:
            logger.warning(f"Article type ID {kwargs.get('id')} not found")
            return Response({"error": "article type not found"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error deleting article type: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#  -------------------- ADMIN DELIVERY OPTION ----------------------------
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['Admin Delivery Option']))
class DeliveryOptionCreateView(generics.CreateAPIView):
    queryset = Delivery_option.objects.all()
    serializer_class = DeliveryOptionSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        data = serializer.validated_data
        delivery_option = data.get('delivery_option', None) 
        if delivery_option and not delivery_option.replace(' ', '').isalpha():
            raise ValidationError({"delivery_option": "Delivery Option must contain only letters and spaces."})
            
        user_fullname = getattr(self.request.user, 'fullname', self.request.user.username)
        delivery_option = serializer.validated_data.get('delivery_option')
        if Delivery_option.objects.filter(delivery_option__iexact=delivery_option, status__in=[1,2]).exists():
         raise ValidationError({"delivery_option": f"'{delivery_option}' already exists and is active."})
        serializer.save(created_by=user_fullname, updated_by=user_fullname)
    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        return Response({"status": True, "message": "Delivery Option created successfully", "data": response.data}, status=status.HTTP_201_CREATED)


@method_decorator(name='get', decorator=swagger_auto_schema(tags=['Admin Delivery Option']))
class DeliveryOptionListView(generics.ListAPIView):
    serializer_class = DeliveryOptionSerializer
    permission_classes = [AllowAny]
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = Delivery_option.objects.filter(status=1).order_by('-id')
        delivery_option = self.request.query_params.get('delivery_option', None)
        if delivery_option:
            queryset = queryset.filter(delivery_option__icontains=delivery_option)
            if not queryset.exists():
                logger.warning(f"{delivery_option} no such delivery option exists")
                raise ValidationError({"delivery_option": f"{delivery_option} no such delivery option exists"})
        return queryset
    def list(self, request, *args, **kwargs):
        serializer = self.get_serializer(self.get_queryset(), many=True)
        return Response({"status": True, "message": "Delivery Options fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)


@method_decorator(name='put', decorator=swagger_auto_schema(tags=['Admin Delivery Option']))
@method_decorator(name='patch', decorator=swagger_auto_schema(tags=['Admin Delivery Option']))
class DeliveryOptionUpdateView(generics.UpdateAPIView):
    queryset = Delivery_option.objects.filter(status=1)
    serializer_class = DeliveryOptionSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def perform_update(self, serializer):
        user = self.request.user
        data = serializer.validated_data
        delivery_option = data.get('delivery_option', None)

        if delivery_option and not delivery_option.replace(' ', '').isalpha():
            logger.warning(f"Invalid delivery option: {delivery_option}")
            raise ValidationError({"delivery_option": "delivery option must contain only letters and spaces."})

        updated_by = getattr(user, "fullname", user.username)
        serializer.save(updated_by=updated_by)

    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"status": True, "message": "Delivery Options updated successfully", "data": response.data}, status=status.HTTP_200_OK)

@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['Admin Delivery Option']))
class DeliveryOptionDeleteView(generics.DestroyAPIView):
    queryset = Delivery_option.objects.filter(status=1)
    serializer_class = DeliveryOptionSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            user = request.user
            instance.status = 3
            instance.updated_by = getattr(user, "fullname", user.username)
            instance.updated_at = timezone.now()
            instance.save(update_fields=['status', 'updated_by', 'updated_at'])
            return Response({"status": True,"message": "Delivery Option deleted successfully."},status=status.HTTP_200_OK)
        except Delivery_option.DoesNotExist:
            logger.warning(f"Delivery Option ID {kwargs.get('id')} not found")
            return Response({"error": "delivery option not found"}, status=404)
        except Exception as e:
            logger.error(f"Error deleting delivery option: {str(e)}")
            return Response({"error": str(e)}, status=500)



# ----------------------- ADMIN BEST DEAL ------------------------------
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['Admin Best Deal']))
class BestDealCreateView(generics.CreateAPIView):
    queryset = Best_deal.objects.filter(status=1)
    serializer_class = BestDealSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        data = serializer.validated_data
        deal_name = data.get('deal_name', None) 
        if deal_name and not deal_name.replace(' ', '').isalpha():
            raise ValidationError({"deal_name": "Deal Name must contain only letters and spaces."})
            
        user_fullname = getattr(self.request.user, 'fullname', self.request.user.username)
        deal_name = serializer.validated_data.get('deal_name')
        if Best_deal.objects.filter(deal_name__iexact=deal_name, status__in=[1,2]).exists():
         raise ValidationError({"deal_name": f"'{deal_name}' already exists and is active."})
        serializer.save(created_by=user_fullname, updated_by=user_fullname)

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        return Response({"status": True, "message": "Best Deal created successfully", "data": response.data}, status=status.HTTP_201_CREATED)

@method_decorator(name='get', decorator=swagger_auto_schema(tags=['Admin Best Deal']))
class BestDealListView(generics.ListAPIView):
    serializer_class = BestDealSerializer
    permission_classes = [AllowAny]
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = Best_deal.objects.filter(status=1).order_by('-id')
        deal_name = self.request.query_params.get('deal_name', None)
        if deal_name:
            queryset = queryset.filter(deal_name__icontains=deal_name)
            if not queryset.exists():
                logger.warning(f"{deal_name} no such deal name exists")
                raise ValidationError({"deal_name": f"{deal_name} no such deal name exists"})
        return queryset
    def list(self, request, *args, **kwargs):
        serializer = self.get_serializer(self.get_queryset(), many=True)
        return Response({"status": True, "message": "Best Deal fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)


@method_decorator(name='put', decorator=swagger_auto_schema(tags=['Admin Best Deal']))
@method_decorator(name='patch', decorator=swagger_auto_schema(tags=['Admin Best Deal']))
class BestDealUpdateView(generics.UpdateAPIView):
    queryset = Best_deal.objects.filter(status=1)
    serializer_class = BestDealSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def perform_update(self, serializer):
        user = self.request.user
        data = serializer.validated_data
        deal_name = data.get('deal_name', None)

        if deal_name and not deal_name.replace(' ', '').isalpha():
            logger.warning(f"Invalid Deal name: {deal_name}")
            raise ValidationError({"deal_name": "deal name must contain only letters and spaces."})

        updated_by = getattr(user, "fullname", user.username)
        serializer.save(updated_by=updated_by)
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"status": True, "message": "Best Deal updated successfully", "data": response.data}, status=status.HTTP_200_OK)


@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['Admin Best Deal']))
class BestDealDeleteView(generics.DestroyAPIView):
    queryset = Best_deal.objects.filter(status=1)
    serializer_class = BestDealSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            user = request.user
            instance.status = 3
            instance.updated_by = getattr(user, "fullname", user.username)
            instance.updated_at = timezone.now()
            instance.save(update_fields=['status', 'updated_by', 'updated_at'])
            return Response({"status": True,"message": "Deal Name deleted successfully."},status=status.HTTP_200_OK)
        except Best_deal.DoesNotExist:
            logger.warning(f"Deal ID {kwargs.get('id')} not found")
            return Response({"error": "deal name not found"}, status=404)
        except Exception as e:
            logger.error(f"Error deleting deal name: {str(e)}")
            return Response({"error": str(e)}, status=500)


# --------------------------- ADMIN APP VERSION ---------------------
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['Admin App Version']))
class AppVersionCreateView(generics.CreateAPIView):
    queryset = App_version.objects.filter(status=1)
    serializer_class = AppVersionSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        data = serializer.validated_data
        app_version = data.get('app_version', None)  
        user_fullname = getattr(self.request.user, 'fullname', self.request.user.username)
        app_version = serializer.validated_data.get('app_version')
        if App_version.objects.filter(app_version__iexact=app_version, status__in=[1,2]).exists():
         raise ValidationError({"app_version": f"'{app_version}' already exists and is active."})
        serializer.save(created_by=user_fullname, updated_by=user_fullname)

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        return Response({"status": True, "message": "App version created successfully", "data": response.data}, status=status.HTTP_201_CREATED)

@method_decorator(name='get', decorator=swagger_auto_schema(tags=['Admin App Version']))
class AppVersionListView(generics.ListAPIView):
    serializer_class = AppVersionSerializer
    permission_classes = [AllowAny]
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = App_version.objects.filter(status=1).order_by('-id')
        app_version = self.request.query_params.get('app_version', None)
        if app_version:
            queryset = queryset.filter(app_version__icontains=app_version)
            if not queryset.exists():
                logger.warning(f"{app_version} no such app version exists")
                raise ValidationError({"app_version": f"{app_version} no such app version exists"})
        return queryset
    def list(self, request, *args, **kwargs):
        serializer = self.get_serializer(self.get_queryset(), many=True)
        return Response({"status": True, "message": "App Version fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)


@method_decorator(name='put', decorator=swagger_auto_schema(tags=['Admin App Version']))
@method_decorator(name='patch', decorator=swagger_auto_schema(tags=['Admin App Version']))
class AppVersionUpdateView(generics.UpdateAPIView):
    queryset = App_version.objects.filter(status=1)
    serializer_class = AppVersionSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def perform_update(self, serializer):
        user = self.request.user
        data = serializer.validated_data
        app_version = data.get('app_version', None)
        updated_by = getattr(user, "fullname", user.username)
        serializer.save(updated_by=updated_by)
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"status": True, "message": "App Version updated successfully", "data": response.data}, status=status.HTTP_200_OK)


@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['Admin App Version']))
class AppVersionDeleteView(generics.DestroyAPIView):
    queryset = App_version.objects.filter(status=1)
    serializer_class = AppVersionSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            user = request.user
            instance.status = 3
            instance.updated_by = getattr(user, "fullname", user.username)
            instance.updated_at = timezone.now()
            instance.save(update_fields=['status', 'updated_by', 'updated_at'])
            return Response({"status": True,"message": "App Version deleted successfully."},status=status.HTTP_200_OK)
        except App_version.DoesNotExist:
            logger.warning(f"Version ID {kwargs.get('id')} not found")
            return Response({"error": "app version not found"}, status=404)
        except Exception as e:
            logger.error(f"Error deleting app version: {str(e)}")
            return Response({"error": str(e)}, status=500)


# -------------------------- ADMIN Base API ----------------------------------

@method_decorator(name='get', decorator=swagger_auto_schema(tags=['Admin Base API']))
class BaseAPIView(APIView):
    permission_classes = [AllowAny]
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            # ------------------- Base Data -------------------
            appVersion = AppVersionSerializer(App_version.objects.filter(status=1), many=True).data
            states = StateSerializer(State_master.objects.filter(status=1), many=True).data
            categories = ServiceSerializer(Service_master.objects.filter(status=1), many=True).data
            documents = document_typeSerializer(document_type.objects.filter(status=1), many=True).data
            company_types = CompanyTypeMaster.objects.filter(status__status_type='Active')

            # ------------------- Onboarding -------------------
            gif = OnboardingScreens.objects.filter(status=1, type=1).order_by("-created_at").first()
            flash_screens = OnboardingScreens.objects.filter(status=1, type=2).order_by("order")[:3]

            onboarding_data = {
                "gif": OnboardingScreenSerializer(gif).data if gif else None,
                "flash_screens": OnboardingScreenSerializer(flash_screens, many=True).data,
            }

            # ------------------- Add Cities under States -------------------
            for state in states:
                state_id = state.get('id')
                cities = City_master.objects.filter(state_id=state_id, status=1).values('id', 'city_name', 'status','latitude', 'longitude')
                state['cities'] = list(cities)

            # ------------------- Company Types with Documents -------------------
            company_data = []
            for company in company_types:
                mappings = CompanyDocumentMapping.objects.filter(company_type=company, status=1).select_related('document_type')
                mapped_docs = [
                    {
                        'id': m.document_type.id,
                        'document_type': m.document_type.document_type
                    } for m in mappings
                ]
                company_data.append({
                    'id': company.id,
                    'company_type': company.company_type,
                    'documents': mapped_docs
                })

            # ------------------- NEW: GST & Best Suited For -------------------
            gst_list = GstMasterSerializer(
                GstMaster.objects.filter(status__status_type='Active').order_by('gst_percentage'),
                many=True
            ).data

            best_suited_for_list = BestSuitedForSerializer(
                Best_suited_for.objects.filter(status=1).order_by('name'),
                many=True
            ).data

            # ------------------- ✅ Terms & Conditions -------------------
            terms_conditions = TermsConditionSerializer(
                Terms_and_condition_master.objects.filter(status=1).order_by('-created_at'),
                many=True
            ).data


            # ------------------- Final Response -------------------
            data = {
                "status": True,
                "message": "Base API Data fetched successfully",
                "data": {
                    "appVersion": appVersion,
                    "states": states,
                    "categories": categories,
                    "company_type_documents": company_data,
                    "gst": gst_list,
                    "best_suited_for": best_suited_for_list,
                    "terms_and_conditions": terms_conditions,  
                    "onboarding": onboarding_data,
                }
            }
            return Response(data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error in BaseAPIView: {str(e)}")
            return Response({
                "status": False,
                "message": "Failed to fetch Base API Data",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
# ---------------- Helper function ----------------
def get_status(status_type):
    try:
        return StatusMaster.objects.get(status_type=status_type)
    except StatusMaster.DoesNotExist:
        logger.error(f"Status '{status_type}' does not exist.")
        raise ValidationError({"status": f"Status '{status_type}' not found."})

# ------------------ CAKES ------------------
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['cakes']))
class CakeCreateView(generics.CreateAPIView):
    queryset = CakeMaster.objects.all()
    serializer_class = CakeMasterSerializer

    def perform_create(self, serializer):
        active_status = get_status('Active')
        serializer.save(status=active_status)
        logger.info("New cake created successfully")


@method_decorator(name='get', decorator=swagger_auto_schema(tags=['cakes']))
class CakeListView(generics.ListAPIView):
    serializer_class = CakeMasterSerializer

    def get_queryset(self):
        active_status = get_status('Active')
        queryset = CakeMaster.objects.filter(status=active_status).order_by('-id')

        flavor = self.request.query_params.get('flavor')
        shape = self.request.query_params.get('shape_name')
        cake_type = self.request.query_params.get('cake_type')

        if flavor:
            queryset = queryset.filter(flavor__iexact=flavor)
        if shape:
            queryset = queryset.filter(shape_name__iexact=shape)
        if cake_type:
            queryset = queryset.filter(cake_type__iexact=cake_type)

        if not queryset.exists():
            logger.warning("No cakes found for the applied filters")
            raise ValidationError({"detail": "No cakes found for the given filters"})
        return queryset


@method_decorator(name='put', decorator=swagger_auto_schema(tags=['cakes']))
@method_decorator(name='patch', decorator=swagger_auto_schema(tags=['cakes']))
class CakeUpdateView(generics.UpdateAPIView):
    queryset = CakeMaster.objects.all()
    serializer_class = CakeMasterSerializer
    lookup_field = 'id'

    def perform_update(self, serializer):
        serializer.save(updated_at=timezone.now())
        logger.info(f"Cake ID {self.get_object().id} updated successfully")


@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['cakes']))
class CakeDeleteView(generics.DestroyAPIView):
    queryset = CakeMaster.objects.all()
    serializer_class = CakeMasterSerializer
    lookup_field = 'id'

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        deleted_status = get_status('Deleted')
        instance.status = deleted_status
        instance.save(update_fields=['status', 'updated_at'])
        logger.info(f"Cake ID {instance.id} deleted successfully")
        return Response({"message": "Cake deleted successfully"}, status=status.HTTP_200_OK)

# ------------------ COMPANY TYPE ------------------
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['company-type']))
class CompanyTypeCreateView(generics.CreateAPIView):
    queryset = CompanyTypeMaster.objects.all()
    serializer_class = CompanyTypeMasterSerializer

    def perform_create(self, serializer):
        name = self.request.data.get('company_type')
        active_status = get_status('Active')
        if CompanyTypeMaster.objects.filter(company_type=name, status=active_status).exists():
            raise ValidationError({"company_type": "This company type already exists"})
        serializer.save(status=active_status)


@method_decorator(name='get', decorator=swagger_auto_schema(tags=['company-type']))
class CompanyTypeListView(generics.ListAPIView):
    serializer_class = CompanyTypeMasterSerializer
    permission_classes = [AllowAny]
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAuthenticated]

    def get_queryset(self):
        active_status = get_status('Active')
        return CompanyTypeMaster.objects.filter(status=active_status).order_by('-id')


@method_decorator(name='put', decorator=swagger_auto_schema(tags=['company-type']))
@method_decorator(name='patch', decorator=swagger_auto_schema(tags=['company-type']))
class CompanyTypeUpdateView(generics.UpdateAPIView):
    queryset = CompanyTypeMaster.objects.all()
    serializer_class = CompanyTypeMasterSerializer
    lookup_field = 'id'

    def perform_update(self, serializer):
        serializer.save(updated_at=timezone.now())


@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['company-type']))
class CompanyTypeDeleteView(generics.DestroyAPIView):
    queryset = CompanyTypeMaster.objects.all()
    serializer_class = CompanyTypeMasterSerializer
    lookup_field = 'id'

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        deleted_status = get_status('Deleted')
        instance.status = deleted_status
        instance.save(update_fields=['status', 'updated_at'])
        return Response({"message": "Company type deleted successfully"}, status=status.HTTP_200_OK)

# ------------------ VENUE TYPE ------------------
@method_decorator(name='get', decorator=swagger_auto_schema(tags=['venue-type']))
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['venue-type']))
class VenueTypeListCreateView(generics.ListCreateAPIView):
    serializer_class = VenueTypeMasterSerializer

    def get_queryset(self):
        active_status = get_status('Active')
        return VenueTypeMaster.objects.filter(status=active_status).order_by('-id')

    def perform_create(self, serializer):
        name = self.request.data.get('venue_type')
        active_status = get_status('Active')
        if VenueTypeMaster.objects.filter(venue_type=name, status=active_status).exists():
            raise ValidationError({"venue_type": "This venue type already exists"})
        serializer.save(status=active_status)


@method_decorator(name='put', decorator=swagger_auto_schema(tags=['venue-type']))
@method_decorator(name='patch', decorator=swagger_auto_schema(tags=['venue-type']))
class VenueTypeUpdateView(generics.UpdateAPIView):
    queryset = VenueTypeMaster.objects.all()
    serializer_class = VenueTypeMasterSerializer
    lookup_field = 'id'

    def perform_update(self, serializer):
        serializer.save(updated_at=timezone.now())


@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['venue-type']))
class VenueTypeDeleteView(generics.DestroyAPIView):
    queryset = VenueTypeMaster.objects.all()
    serializer_class = VenueTypeMasterSerializer
    lookup_field = 'id'

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        deleted_status = get_status('Deleted')
        instance.status = deleted_status
        instance.save(update_fields=['status', 'updated_at'])
        return Response({"message": "Venue type deleted successfully"}, status=status.HTTP_200_OK)

# ------------------ OPPVENUZ CHOICE ------------------
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['OPPVENUZ CHOICE']))
class OppvenuzChoiceCreateView(APIView):
    def post(self, request):
        serializer = OppvenuzChoiceMasterSerializer(data=request.data)
        if serializer.is_valid():
            active_status = get_status('Active')
            serializer.save(status=active_status)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(name='get', decorator=swagger_auto_schema(tags=['OPPVENUZ CHOICE']))
class OppvenuzChoiceListView(APIView):
    def get(self, request, pk=None):
        if pk:
            obj = get_object_or_404(OppvenuzChoiceMaster, pk=pk)
            serializer = OppvenuzChoiceMasterSerializer(obj)
            return Response(serializer.data)
        active_status = get_status('Active')
        objs = OppvenuzChoiceMaster.objects.filter(status=active_status).order_by('-id')
        serializer = OppvenuzChoiceMasterSerializer(objs, many=True)
        return Response(serializer.data)

@method_decorator(name='put', decorator=swagger_auto_schema(tags=['OPPVENUZ CHOICE']))
@method_decorator(name='patch', decorator=swagger_auto_schema(tags=['OPPVENUZ CHOICE']))
class OppvenuzChoiceUpdateView(APIView):
    def put(self, request, pk):
        obj = get_object_or_404(OppvenuzChoiceMaster, pk=pk)
        serializer = OppvenuzChoiceMasterSerializer(obj, data=request.data)
        if serializer.is_valid():
            serializer.save(updated_at=timezone.now())
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        obj = get_object_or_404(OppvenuzChoiceMaster, pk=pk)
        serializer = OppvenuzChoiceMasterSerializer(obj, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save(updated_at=timezone.now())
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['OPPVENUZ CHOICE']))
class OppvenuzChoiceDeleteView(APIView):
    def delete(self, request, pk):
        obj = get_object_or_404(OppvenuzChoiceMaster, pk=pk)
        deleted_status = get_status('Deleted')
        obj.status = deleted_status
        obj.save(update_fields=['status', 'updated_at'])
        return Response({"message": "Choice deleted successfully"}, status=status.HTTP_200_OK)

# ------------------ GST ------------------

@method_decorator(name='post', decorator=swagger_auto_schema(tags=['GST']))
class GstMasterCreateView(generics.CreateAPIView):
    queryset = GstMaster.objects.all()
    serializer_class = GstMasterSerializer

@method_decorator(name='get', decorator=swagger_auto_schema(tags=['GST']))
class GstMasterListView(generics.ListAPIView):
    serializer_class = GstMasterSerializer

    def get_queryset(self):
        return GstMaster.objects.filter(status__status_type__in=['Active', 'Inactive']).order_by('-id')

@method_decorator(name='put', decorator=swagger_auto_schema(tags=['GST']))
@method_decorator(name='patch', decorator=swagger_auto_schema(tags=['GST']))
class GstMasterUpdateView(generics.UpdateAPIView):
    queryset = GstMaster.objects.all()
    serializer_class = GstMasterSerializer
    lookup_field = 'pk'

@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['GST']))
class GstMasterDeleteView(generics.DestroyAPIView):
    queryset = GstMaster.objects.all()
    serializer_class = GstMasterSerializer
    lookup_field = 'pk'

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        deleted_status = get_status('Deleted')
        instance.status = deleted_status
        instance.save(update_fields=['status', 'updated_at'])
        return Response({"message": "GST deleted successfully"}, status=status.HTTP_200_OK)
    
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['Social Media'])) 
class SocialMediaUploadView(generics.CreateAPIView):
    queryset = Social_media_master.objects.all()
    serializer_class = SocialMediaSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request, *args, **kwargs):
        media_name = request.data.get("media_name")
        if media_name:
            media_name = media_name.strip().strip('"')

        image = request.FILES.get("media_image")

        if not media_name or not image:
            logger.warning("Missing media_name or media_image in upload request.")
            return Response(
                {
                    "message": "Both media_name and media_image are required.",
                    "status": False
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if Social_media_master.objects.filter(media_name__iexact=media_name, status__in=[1,2]).exists():
            return Response(
                {"message": f"Social media '{media_name}' already exists.", "status": False},
                status=status.HTTP_400_BAD_REQUEST
            )

        max_size_mb = 5
        if image.size > max_size_mb * 1024 * 1024:
            logger.warning(f"File too large: {image.size / (1024 * 1024):.2f} MB")
            return Response(
                {
                    "message": f"Maximum file size is {max_size_mb} MB.",
                    "status": False
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        valid_extensions = (".png", ".jpg", ".jpeg", ".svg", ".webp")
        ext = image.name.lower().rsplit(".", 1)[-1]
        if f".{ext}" not in valid_extensions:
            logger.warning(f"Unsupported file extension: .{ext}")
            return Response(
                {
                    "message": f"Unsupported file extension. Allowed: {', '.join(valid_extensions)}",
                    "status": False
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        s3 = boto3.client(
            "s3",
            aws_access_key_id=config("s3AccessKey"),
            aws_secret_access_key=config("s3Secret"),
        )

        filename = f"{image.name}"
        key = f"social_media/{filename}"
        bucket = config("S3_BUCKET_NAME")

        try:
            s3.upload_fileobj(
                Fileobj=image,
                Bucket=bucket,
                Key=key,
                ExtraArgs={"ACL": "public-read", "ContentType": image.content_type},
            )
        except Exception as e:
            logger.error(f"Failed to upload image to S3: {str(e)}")
            return Response(
                {
                    "message": "Failed to upload image.",
                    "error": str(e),
                    "status": False
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        media_url = f"https://{bucket}.s3.amazonaws.com/{key}"

        serializer = self.get_serializer(data={
            "media_name": media_name,
            "media_image": media_url
        })
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        return Response(
            {
                "message": "Social media uploaded successfully.",
                "data": serializer.data,
                "status": True
            },
            status=status.HTTP_201_CREATED
        )

    def perform_create(self, serializer):
        user_fullname = getattr(self.request.user, 'fullname', self.request.user.username)
        serializer.save(
            created_by=user_fullname,
            updated_by=user_fullname
        )

@method_decorator(name='get', decorator=swagger_auto_schema(tags=['Social Media']))
class SocialMediaList(generics.ListAPIView):
    queryset = Social_media_master.objects.all()
    serializer_class = SocialMediaSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        return Social_media_master.objects.filter(status__in=[1,2]).order_by("media_name")

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True)

            if not queryset.exists():
                return Response(
                    {
                        "message": "No social media records found.",
                        "data": [],
                        "status": True
                    },
                    status=status.HTTP_200_OK
                )

            return Response(
                {
                    "message": "Social media list fetched successfully.",
                    "data": serializer.data,
                    "status": True
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.error(f"Error fetching social media list: {str(e)}")
            return Response(
                {
                    "message": "Failed to fetch social media list.",
                    "error": str(e),
                    "status": False
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@method_decorator(name='put', decorator=swagger_auto_schema(tags=['Social Media']))
@method_decorator(name='patch', decorator=swagger_auto_schema(tags=['Social Media']))
class SocialMediaUpdateView(generics.UpdateAPIView):
    serializer_class = SocialMediaSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    lookup_field = 'id'

    def get_queryset(self):
        # Only allow updates for objects with status 1 or 2
        return Social_media_master.objects.filter(status__in=[1, 2])

    def perform_update(self, serializer):
        # Add updated_by
        data_to_save = {"updated_by": getattr(self.request.user, 'fullname', self.request.user.username)}

        # Handle S3 upload
        media_file = self.request.FILES.get("media_image")
        if media_file:
            s3 = boto3.client(
                "s3",
                aws_access_key_id=config("s3AccessKey"),
                aws_secret_access_key=config("s3Secret"),
            )
            bucket = config("S3_BUCKET_NAME")
            instance = self.get_object()  # current instance

            # Delete old file if exists
            old_url = getattr(instance, 'media_image', None)
            if old_url and bucket in old_url:
                old_key = old_url.split(f"https://{bucket}.s3.amazonaws.com/")[-1]
                try:
                    s3.delete_object(Bucket=bucket, Key=old_key)
                except Exception as e:
                    logger.warning(f"Failed to delete old image: {str(e)}")

            # Upload new file
            new_key = f"social_media/{media_file.name}"
            try:
                s3.upload_fileobj(
                    media_file,
                    bucket,
                    new_key,
                    ExtraArgs={"ACL": "public-read", "ContentType": media_file.content_type},
                )
                new_url = f"https://{bucket}.s3.amazonaws.com/{new_key}"
                data_to_save["media_image"] = new_url
            except Exception as e:
                logger.error(f"Failed to upload new image: {str(e)}")
                raise serializer.ValidationError(f"Failed to upload image: {str(e)}")

        serializer.save(**data_to_save)

    def patch(self, request, *args, **kwargs):
        """Override patch to return custom response format"""
        partial = True
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        return Response(
            {
                "message": "Social media updated successfully.",
                "data": serializer.data,
                "status": True
            },
            status=status.HTTP_200_OK
        )

@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['Social Media']))
class SocialMediaDeleteView(generics.DestroyAPIView):
    queryset = Social_media_master.objects.all()
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()

            old_url = instance.media_image
            if old_url and config("S3_BUCKET_NAME") in old_url:
                s3 = boto3.client(
                    "s3",
                    aws_access_key_id=config("s3AccessKey"),
                    aws_secret_access_key=config("s3Secret"),
                )
                bucket = config("S3_BUCKET_NAME")
                old_key = old_url.split(f"https://{bucket}.s3.amazonaws.com/")[-1]
                s3.delete_object(Bucket=bucket, Key=old_key)

            instance.delete()

            return Response({"message": "Deleted successfully."}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"message": f"Deletion failed: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['Terms & Conditions']))
class TermsAndConditionsView(generics.CreateAPIView):
    queryset = Terms_and_condition_master.objects.all()
    serializer_class = TermsConditionSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]      

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        title = serializer.validated_data.get('title')
        content = serializer.validated_data.get('content')

        if Terms_and_condition_master.objects.filter(
            title__iexact=title,
            content__iexact=content,
            status__in=[1, 2]  
        ).exists():
            raise ValidationError("This Terms & Conditions already exists.")

        self.perform_create(serializer)

        return Response(
            {
                "message": "Terms & Conditions created successfully",
                "data": serializer.data,
                "status": True
            },
            status=status.HTTP_201_CREATED
        )

@method_decorator(name='get', decorator=swagger_auto_schema(tags=['Terms & Conditions']))
class TermsAndConditionsListView(generics.ListAPIView):
    serializer_class = TermsConditionSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        try:
            queryset = Terms_and_condition_master.objects.filter(status__in=[1, 2])
            return queryset
        except Exception as e:
            logger.error(f"Error fetching Terms and Conditions list: {str(e)}", exc_info=True)
            return Terms_and_condition_master.objects.none()

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True)
            return Response(
                {
                    "message": "Terms & Conditions fetched successfully",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error('error', "Unexpected error in Terms & Conditions list API", exc=e)
            return Response(
                {"message": "Failed to fetch Terms & Conditions."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@method_decorator(name='put', decorator=swagger_auto_schema(tags=['Terms & Conditions']))
@method_decorator(name='patch', decorator=swagger_auto_schema(tags=['Terms & Conditions']))
class TermsAndConditionsUpdateView(generics.UpdateAPIView):
    queryset = Terms_and_condition_master.objects.filter(status__in=[1,2])
    serializer_class = TermsConditionSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def update(self, request, *args, **kwargs):
        try:
            partial = kwargs.pop('partial', False)
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)

            user = request.user
            user_fullname = getattr(user, 'fullname', user.username)
            title = serializer.validated_data.get('title')
            content = serializer.validated_data.get('content')

            duplicate = Terms_and_condition_master.objects.filter(
                title__iexact=title,
                content__iexact=content,
                status__in=[1, 2]
            ).exclude(id=instance.id)

            if duplicate.exists():
                logger.warning(f"Duplicate Terms & Conditions found for title '{title}' by '{user_fullname}'")
                raise ValidationError("A Terms & Conditions with the same title and content already exists.")

            instance = serializer.save(updated_by=user_fullname)

            return Response({
                "message": "Terms & Conditions updated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Unexpected error during Terms update: {str(e)}", exc_info=True)
            return Response(
                {"message": "An unexpected error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['Terms & Conditions']))
class TermsAndConditionsDeleteView(generics.DestroyAPIView):
    queryset = Terms_and_condition_master.objects.filter(status__in=[1, 2])  
    serializer_class = TermsConditionSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def delete(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            user_fullname = getattr(request.user, 'fullname', request.user.username)

            instance.status = 3
            instance.updated_by = user_fullname
            instance.save(update_fields=['status', 'updated_by', 'updated_at'])

            return Response(
                {"message": "Terms & Conditions soft-deleted successfully", "status": True},
                status=status.HTTP_200_OK
            )

        except Terms_and_condition_master.DoesNotExist:
            return Response(
                {"message": "Terms & Conditions not found or already deleted", "status": False},
                status=status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            logger.error(f"Unexpected error while soft deleting Terms & Conditions: {str(e)}", exc_info=True)
            return Response(
                {"message": "An unexpected error occurred", "status": False},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@method_decorator(name='get', decorator=swagger_auto_schema(tags=['service Registration charges']))
class GetRegistrationChargeView(APIView):
    def get(self, request, id, *args, **kwargs):
        try:
            service = Service_master.objects.get(id=id, status__in=[1, 2])
            return Response({
                "service_name": service.service_name,
                "registration_charges": service.registration_charges
            }, status=status.HTTP_200_OK)
        except Service_master.DoesNotExist:
            return Response(
                {"error": "Service not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )

# ------------------- OPPVENUZ QUESTION ANSWER ---------------------------
@method_decorator(name='post', decorator=swagger_auto_schema(tags=['Admin Oppvenuz Question Answer']))
class QuestionAnswerCreateView(generics.CreateAPIView):
    queryset = Oppvenuz_ques_ans_master.objects.all()
    serializer_class = QuestionAnswerSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        data = serializer.validated_data
        question = data.get('question', None)  
        user_fullname = getattr(self.request.user, 'fullname', self.request.user.username)
        question = serializer.validated_data.get('question')
        if Oppvenuz_ques_ans_master.objects.filter(question__iexact=question, status__in=[1,2]).exists():
         raise ValidationError({"question": f"'{question}' already exists and is active."})
        serializer.save(created_by=user_fullname, updated_by=user_fullname)

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        return Response({"status": True, "message": " created successfully", "data": response.data}, status=status.HTTP_201_CREATED)


@method_decorator(name='get', decorator=swagger_auto_schema(tags=['Admin Oppvenuz Question Answer']))
class QuestionAnswerListView(generics.ListAPIView):
    serializer_class = QuestionAnswerSerializer
    permission_classes = [AllowAny]
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = Oppvenuz_ques_ans_master.objects.filter(status=1).order_by('-id')
        question = self.request.query_params.get('question', None)
        if question:
            queryset = queryset.filter(question__icontains=question)
            if not queryset.exists():
                logger.warning(f"{question} no such Details")
                raise ValidationError({"question": f"{question} no such Details exists"})
        return queryset
    def list(self, request, *args, **kwargs):
        serializer = self.get_serializer(self.get_queryset(), many=True)
        return Response({"status": True, "message": "Details fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)


@method_decorator(name='put', decorator=swagger_auto_schema(tags=['Admin Oppvenuz Question Answer']))
@method_decorator(name='patch', decorator=swagger_auto_schema(tags=['Admin Oppvenuz Question Answer']))
class QuestionAnswerUpdateView(generics.UpdateAPIView):
    queryset = Oppvenuz_ques_ans_master.objects.filter(status=1)
    serializer_class = QuestionAnswerSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def perform_update(self, serializer):
        user = self.request.user
        data = serializer.validated_data
        question = data.get('question', None)
        updated_by = getattr(user, "fullname", user.username)
        serializer.save(updated_by=updated_by)
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"status": True, "message": "Details updated successfully", "data": response.data}, status=status.HTTP_200_OK)


@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['Admin Oppvenuz Question Answer']))
class QuestionAnswerDeleteView(generics.DestroyAPIView):
    queryset = Oppvenuz_ques_ans_master.objects.filter(status=1)
    serializer_class = QuestionAnswerSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            user = request.user
            instance.status = 3
            instance.updated_by = getattr(user, "fullname", user.username)
            instance.updated_at = timezone.now()
            instance.save(update_fields=['status', 'updated_by', 'updated_at'])
            return Response({"status": True,"message": "Details deleted successfully."},status=status.HTTP_200_OK)
        except Payment_type.DoesNotExist:
            logger.warning(f" ID {kwargs.get('id')} not found")
            return Response({"error": "not found"}, status=404)
        except Exception as e:
            logger.error(f"Error deleting: {str(e)}")
            return Response({"error": str(e)}, status=500)


class UploadOnboardingView(APIView):
    permission_classes = [AllowAny]

    def upload_to_s3(self, file_obj):
        s3 = boto3.client(
            "s3",
            aws_access_key_id=config("s3AccessKey"),
            aws_secret_access_key=config("s3Secret"),
        )
        bucket = config("S3_BUCKET_NAME")
        key = f"onboarding/{file_obj.name}"
        s3.upload_fileobj(file_obj, bucket, key, ExtraArgs={"ACL": "public-read"})
        return f"https://{bucket}.s3.amazonaws.com/{key}"

    def post(self, request):
        file = request.FILES.get("file")
        title = request.data.get("title")
        type_ = int(request.data.get("type", 2))  # 1 = GIF, 2 = Flash
        order = int(request.data.get("order", 0))

        if not file:
            return Response({"error": "File is required"}, status=status.HTTP_400_BAD_REQUEST)

        allowed_ext = (".png", ".jpg", ".jpeg", ".gif")
        if not file.name.lower().endswith(allowed_ext):
            return Response({"error": "Invalid file type"}, status=status.HTTP_400_BAD_REQUEST)

        # Upload to S3
        file_url = self.upload_to_s3(file)
        media = {"image": file_url}

        screen = OnboardingScreens.objects.create(
            title=title,
            media=media,
            type=type_,
            order=order,
        )

        return Response(OnboardingScreenSerializer(screen).data, status=status.HTTP_201_CREATED)

class GetOnboardingFlowView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        gif = OnboardingScreens.objects.filter(status=1, type=1).order_by("-created_at").first()
        flash_screens = OnboardingScreens.objects.filter(status=1, type=2).order_by("order")[:3]

        response = {
            "gif": OnboardingScreenSerializer(gif).data if gif else None,
            "flash_screens": OnboardingScreenSerializer(flash_screens, many=True).data,
        }
        return Response(response, status=status.HTTP_200_OK)

@method_decorator(name='post', decorator=swagger_auto_schema(tags=['Company Document Mapping']))
class CompanyDocumentMappingCreateView(generics.CreateAPIView):
    queryset = CompanyDocumentMapping.objects.all()
    serializer_class = CompanyDocumentMappingSerializer

    def perform_create(self, serializer):
        user_fullname = getattr(self.request.user, 'fullname', self.request.user.username)
        company_type = serializer.validated_data.get('company_type')
        document_type_obj = serializer.validated_data.get('document_type')

        
        if CompanyDocumentMapping.objects.filter(
            company_type=company_type, document_type=document_type_obj, status__in=[1, 2]
        ).exists():
            raise ValidationError({"detail": "This document is already mapped with the selected company type."})

        serializer.save(created_by=user_fullname, updated_by=user_fullname)


@method_decorator(name='get', decorator=swagger_auto_schema(tags=['Company Document Mapping']))
class CompanyDocumentMappingListView(generics.ListAPIView):
    serializer_class = CompanyDocumentMappingSerializer

    def get_queryset(self):
        return CompanyDocumentMapping.objects.filter(status=1).select_related('company_type', 'document_type')


@method_decorator(name='delete', decorator=swagger_auto_schema(tags=['Company Document Mapping']))
class CompanyDocumentMappingDeleteView(generics.DestroyAPIView):
    queryset = CompanyDocumentMapping.objects.filter(status=1)
    serializer_class = CompanyDocumentMappingSerializer
    lookup_field = 'pk'

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            instance.status = 3  
            instance.updated_by = getattr(request.user, 'fullname', request.user.username)
            instance.updated_at = timezone.now()
            instance.save(update_fields=['status', 'updated_by', 'updated_at'])
            return Response({"status": True, "message": "Mapping deleted successfully."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status": False, "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
