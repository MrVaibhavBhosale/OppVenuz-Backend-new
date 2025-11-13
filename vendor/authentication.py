from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import AuthenticationFailed
from vendor.models import Vendor_registration

class VendorJWTAuthentication(JWTAuthentication):
    def get_user(self, validated_token):
        """
        Override SimpleJWT's default user fetching to use Vendor_registration.
        """
        vendor_id = validated_token.get("user_id")
        if not vendor_id:
            raise AuthenticationFailed("Token missing vendor ID", code="user_not_found")

        try:
            return Vendor_registration.objects.get(id=vendor_id)
        except Vendor_registration.DoesNotExist:
            raise AuthenticationFailed("User not found", code="user_not_found")