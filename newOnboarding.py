from extras.scripts import *
from django.utils.text import slugify
from dcim.models import DeviceRole, Site, Platform

class NewOnboardScript(Script):

    class Meta:
        name = "New Onboarding"
        description = "Add/Update new device"

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
    device_ip = TextVar(
        description="IP List, 1 IP or hostname per line",
        required=True
    )

    def run(self, data, commit):
        self.log_success(f"Test Successful")
        self.log_success(f"{data['site_name']}")
        self.log_success(f"{data['device_role']}")
        self.log_success(f"{data['device_platform']}")
        self.log_success(f"{data}")
        self.log_success(f"{dir(data['site_name'])}")
        self.log_success(f"{data['device_ip']}")
        self.log_success(f"{type(data['device_ip'])}")