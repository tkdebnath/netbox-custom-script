from extras.scripts import *
from django.utils.text import slugify
from dcim.models import DeviceRole, Site, Platform
import os
from cisco_netbox_onboarding import new_onboard

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
        if os.getenv("NETMIKO_USERNAME") and os.getenv("NETMIKO_PASSWORD") and os.getenv("URL") and os.getenv("API_KEY"):
            ip_list = data['device_ip'].split('\r\n')
            self.log_info(f"Onboard process initiated for {len(ip_list)} devices")
            
            # call for onboard function
            results = new_onboard(ip_list=ip_list)
            if results:
                for result in results:
                    if result.get('hostname', None):
                        self.log_success(f"Successfully onboarded {result['ip']}, {result['hostname']}")
                    
                    if not result.get('hostname', None):
                        self.log_failure(f"Failed onboarding {result['ip']}")
