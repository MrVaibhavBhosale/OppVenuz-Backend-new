from .models import StatusMaster

def get_status(status_name):
    try:
        return StatusMaster.objects.get(status_type=status_name)
    except StatusMaster.DoesNotExist:
        # Create if not exists
        return StatusMaster.objects.create(status_type=status_name)
