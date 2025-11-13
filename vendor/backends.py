from django.contrib.auth.backends import BaseBackend
from .models import Vendor_registration

class VendorAuthBackend(BaseBackend):
    def authenticate(self, request, username=None, mpin=None, **kwargs):
        try:
            # Vendor can log in using email or contact number
            if '@' in username:
                user = Vendor_registration.objects.get(email=username)
            else:
                user = Vendor_registration.objects.get(contact_no=username)

            # Check MPIN hash (using check_mpin method)
            if user.check_mpin(mpin):
                return user
        except Vendor_registration.DoesNotExist:
            return None
        return None

    def get_user(self, user_id):
        try:
            return Vendor_registration.objects.get(pk=user_id)
        except Vendor_registration.DoesNotExist:
            return None