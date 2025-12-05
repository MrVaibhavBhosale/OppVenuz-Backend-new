from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import AuthenticationFailed
from vendor.models import Vendor_registration, BlacklistedToken

class VendorJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        token_str = raw_token.decode() if isinstance(raw_token, bytes) else raw_token

        #  Check if access token is blacklisted
        if BlacklistedToken.objects.filter(token=token_str).exists():
            raise AuthenticationFailed("Token is blacklisted", code="token_blacklisted")

        validated_token = self.get_validated_token(raw_token)
        user = self.get_user(validated_token)
        return (user, validated_token)
    
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