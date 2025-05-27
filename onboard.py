from extras.scripts import *
from django.utils.text import slugify
from dcim.models import DeviceRole, Site, Platform
import os

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

        # if not verify_env():
        #     self.log_failure(f"Missing environment value")
        #     return
        
        device_list = data['device_ip'].split('\r\n')
        self.log_info(f"Onboard process initiated for {len(device_list)} devices")
        self.log_info(f"{len(device_list)}")

        self.log_info(f"{data['site_name']}")
        self.log_info(f"{dir(data['site_name'])}")
        

def verify_env():
    if os.getenv("NETMIKO_USERNAME") and os.getenv("NETMIKO_PASSWORD"):
        return True
    return False