from extras.scripts import *
from django.utils.text import slugify
from dcim.models import DeviceRole, Site, Platform

class NewBranchScript(Script):

    class Meta:
        name = "New Branch"
        description = "Provision a new branch site"

    site_name = ObjectVar(
        description="Site To Update",
        model=Site,
        required=False
    )
    device_role = ObjectVar(
        description="Device role",
        model=DeviceRole,
        required=False
    )
    device_platform = ObjectVar(
        description="Plaform",
        model=Platform,
        required=False
    )

def run(self, data, commit):
    self.log_success(f"Test Successful")
    self.log_success(f"{data['site_name']}")