from extras.scripts import *
from django.utils.text import slugify
from dcim.models import DeviceRole, Site, Platform, Device, Interface, Cable, Site, DeviceType, ModuleType, ModuleBay, Module, VirtualChassis
from ipam.models import IPAddress

from netmiko import ConnectHandler
from multiprocessing.dummy import Pool as ThreadPool
import genie

from utilities.exceptions import AbortScript
import os
import re
from itertools import islice
from time import sleep

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

        if not verify_env():
            self.log_failure(f"Missing environment value")
            raise AbortScript("Values not set for NETMIKO_USERNAME, NETMIKO_PASSWORD")
        
        device_list = data['device_ip'].split('\r\n')
        self.log_info(f"Onboard process initiated for {len(device_list)} devices")
        self.log_info(f"Selected site: {data['site_name']}")

        # Create batches
        batch_size = 5
        result = list(chunk_list_islice(device_list, batch_size))

        for batch in result:
            self.log_debug(f"Batch: {batch}")
            NewOnboardScript.new_onboard(ip_list=batch, threads=batch_size)
            sleep(10)

    def new_onboard(self, ip_list: list, threads: int=10):
        
        if not os.getenv("NETMIKO_USERNAME"):
            raise BaseException('username is missing')
        if not os.getenv("NETMIKO_PASSWORD"):
            raise BaseException('password is missing')
        if not os.getenv("NETMIKO_SECRET"):
            pass
    
        threads = ThreadPool(threads)
        results = threads.map(NewOnboardScript.check_host, ip_list)
        threads.close()
        threads.join()
        
    
    def check_host(self, ip):

        host = {
            'host': ip,
            'device_type': 'cisco_xe',
            'fast_cli': False,
            'username': os.getenv("NETMIKO_USERNAME"),
            'password': os.getenv("NETMIKO_PASSWORD"),
        }
        
        if os.getenv("NETMIKO_SECRET"):
            host['secret'] = os.getenv("NETMIKO_SECRET")
        
        self.log_info(f"Connecting to: {ip}")
        try:
            net_connect = ConnectHandler(**host)
            
            #without enable mode
            if ">" in net_connect.find_prompt():
                pass
            hostname = net_connect.find_prompt().replace(">", "").replace("#", "").upper()
            
            site = hostname[0:3].upper()
            # check if site already present in netbox or not
            obj_site = Site.objects.get(name=site)
            if not obj_site:
                site = "XXX"

            
            self.log_info(f"Connected to: {hostname}, IP/Host: {ip}, Site: {site}")
            
            show_version = net_connect.send_command(command_string="show version", use_genie=True, read_timeout=300)
            show_interface = net_connect.send_command(command_string="show interface", use_genie=True, read_timeout=300)
            # show_inventory = net_connect.send_command(command_string="show inventory", use_genie=True, read_timeout=300)
            show_inventory = "{'dummy': True}"
            show_cdp = net_connect.send_command(command_string="show cdp neighbors detail", use_genie=True, read_timeout=300)
            
            self.log_info(f"{hostname}: Collecting data")
            
            if isinstance(show_version, genie.conf.base.utils.QDict):
                show_version = dict(show_version)
            if isinstance(show_interface, genie.conf.base.utils.QDict):
                show_interface = dict(show_interface)
            if isinstance(show_inventory, genie.conf.base.utils.QDict):
                show_inventory = dict(show_inventory)
            if isinstance(show_cdp, genie.conf.base.utils.QDict):
                show_cdp = dict(show_cdp)
            
            self.log_info(f"{hostname}: Initiating onboarding/update process")

            obj_onboard = Onboarding(hostname=hostname, site=site, version=show_version, interfaces=show_interface, inventory=show_inventory)
            obj_onboard.cdp_neighbors_detail = show_cdp
            obj_onboard.automatic()
            net_connect.disconnect()
            self.log_info(f"{hostname}: onboarding/update process complete")
            
            return {'ip': ip, 'hostname': hostname, 'msg': 'success'}
        except Exception as msg:
            self.log_failure(f"{ip}: onboarding/update process failed, msg: {msg}")
            return {'ip': ip, 'msg': msg}
        
        

def verify_env():
    if not os.getenv("NETMIKO_USERNAME"):
        return False
    if not os.getenv("NETMIKO_PASSWORD"):
        return False
    
    return True



def chunk_list_islice(original_list, chunk_size):
    it = iter(original_list)
    while True:
        chunk = list(islice(it, chunk_size))
        if not chunk:
            break
        yield chunk




class Adjacency:
    def __init__(self, connection_type, hostname, adjacency_table) -> None:
        self.connection_type = connection_type
        self.hostname = hostname
        self.adjacency_table = adjacency_table
        self.connection_records = None

        self.connection_table()

    def connection_table(self):
        if self.connection_type in ["Stack"]:
            pass

        if self.connection_type in ["Normal"]:
            """
            cdp neighbor table
            """
            if isinstance(self.adjacency_table, dict) and self.adjacency_table.get('index', None) and len(self.adjacency_table['index']) > 0:
                con_record = []
                neighbors = self.adjacency_table['index']
                for index in neighbors:
                    if neighbors[index].get('device_id', None) and neighbors[index].get('local_interface', None) and neighbors[index].get('port_id', None):
                        remote_device_name = neighbors[index]['device_id'].split('.')[0].split('(')[0].upper()
                        remote_port = neighbors[index]['port_id'].split('.')[0] # fix issue where cdp adjacency show subinterface
                        local_device_name = self.hostname
                        local_port = neighbors[index]['local_interface'].split('.')[0]# fix issue where cdp adjacency show subinterface
                        
                        # finding actual local device name
                        obj_vc = _VirtualChassis(hostname=self.hostname)
                        if not obj_vc.flag_vc_presence:
                            # single device
                            pass
                        
                        if obj_vc.flag_vc_presence:
                            # stack found
                            if local_port == "GigabitEthernet0/0" or local_port == "FastEthernet0" or local_port == "FastEthernet1":
                                if obj_vc.master:
                                    local_device_name = obj_vc.master
                                
                                if not obj_vc.master:
                                    local_device_name = f"{local_device_name}_1"
                                    
                            if local_port != "GigabitEthernet0/0" and local_port != "FastEthernet0" and local_port != "FastEthernet1":
                                swi_num = switch_number_interface(interface=local_port)
                                if swi_num:
                                    local_device_name = f"{local_device_name}_{swi_num}"
                        
                        # finding actual remote device name
                        obj_vc = _VirtualChassis(hostname=remote_device_name)
                        if not obj_vc.flag_vc_presence:
                            # single device found
                            pass
                        
                        if obj_vc.flag_vc_presence:
                            # stack found
                            if remote_port == "GigabitEthernet0/0" or remote_port == "FastEthernet0" or remote_port == "FastEthernet1":
                                if obj_vc.master:
                                    remote_device_name = obj_vc.master
                                
                                if not obj_vc.master:
                                    remote_device_name = f"{remote_device_name}_1"
                                    
                            if remote_port != "GigabitEthernet0/0" and remote_port != "FastEthernet0" and remote_port != "FastEthernet1":
                                swi_num = switch_number_interface(interface=remote_port)
                                if swi_num:
                                    remote_device_name = f"{remote_device_name}_{swi_num}"
                        
                        # final validate presense of remove device
                        obj_remote_device = Device.objects.get(name=remote_device_name)
                        if obj_remote_device:
                            loop_connection = {'a_device': local_device_name, 'a_port': local_port,
                                            'b_device': remote_device_name, 'b_port': remote_port}
                            con_record.append(loop_connection)

                if len(con_record) > 0:
                    self.connection_records = con_record

class AdjacencyStackPorts(Adjacency):
    def __init__(self, hostname, adjacency_table) -> None:
        super().__init__("Stack", hostname, adjacency_table)

class AdjacencyNormal(Adjacency):
    def __init__(self, hostname, adjacency_table) -> None:
        super().__init__("Normal", hostname, adjacency_table)



class Connection:
    def __init__(self, a_device, a_port, b_device, b_port) -> None:
        self.a_device = a_device
        self.a_port = a_port
        self.b_device = b_device
        self.b_port = b_port
        self.a_obj_port = None
        self.b_obj_port = None
        self.cable = None
        self.a_terminations = None
        self.b_terminations = None
        self.cabling_required = True

        a_obj_port = Interface.objects.get(device=self.a_device, name=self.a_port)
        b_obj_port = Interface.objects.get(device=self.b_device, name=self.b_port)

        if not a_obj_port:
            raise ValueError(f"{self.a_device} has no port: {self.a_port}")
        
        if not b_obj_port:
            raise ValueError(f"{self.b_device} has no port: {self.b_port}")
        
        
        self.a_terminations = a_obj_port.id
        self.b_terminations = b_obj_port.id
        self.a_obj_port = a_obj_port
        self.b_obj_port = b_obj_port
    
        #Check if cabling required or not
        if self.a_obj_port.cable and self.b_obj_port.cable:
            if self.a_obj_port.cable.id == self.b_obj_port.cable.id:
                self.cable = a_obj_port.cable.id
                self.cabling_required = False
        
        #Delete existing cable if any cable found connected on any end
        if self.cabling_required:
            if self.a_obj_port.cable:
                self.a_obj_port.cable.delete()
            if self.b_obj_port.cable:
                self.b_obj_port.cable.delete()


    def make_connection(self):
        if not self.cabling_required:
            return self.cable

        if self.a_terminations and self.b_terminations:
            obj_cable = Cable(
                a_terminations = [{"object_type": "dcim.interface", "object_id": self.a_terminations}],
                b_terminations = [{"object_type": "dcim.interface", "object_id": self.b_terminations}],
            )
            if obj_cable:
                self.cable = obj_cable.id
                return self.cable
            if not obj_cable:
                return None
        
        raise ValueError(f"Cable can't be connected")


class InvalidInputError(Exception):
    """Custom exception for MyClass."""
    pass

class DeviceCreateError(Exception):
    """Custom exception for MyClass."""
    pass


class _Device:
    def __init__(self, role, device, site, device_type) -> None:
        self.role = role
        self.device = device
        self.site = Site.objects.get(name=site)
        self.device_type = DeviceType.objects.get(part_number=device_type)
        self.serial = None
        self.mac_address = None
        self.software = None
        self.vc_name = None
        self.vc_master = False
        self.stack_swi_num = None
        self.uuid_device = None
        self.flag_device_present = False

        if not self.site:
            raise ValueError(f"Site: {site}, is not present")
        
        if not self.device_type:
            raise ValueError(f"Device type: {device_type}, is not present")
    
    def update_db(self) -> dict:
        if self.role in ["Router", "Access Switch", "Access Point", "Wireless Controller", "Firewall", "Meraki MX", "Meraki MS", "Meraki MR"]:
            obj_device = Device.objects.get(name=self.device)
            if not obj_device:
                obj_device = Device(
                    name = self.device.upper(),
                    device_type = self.device_type.id,
                    role = DeviceRole.objects.get(name=self.role).id,
                    site = self.site.id,
                    status = "active"
                )
            if obj_device:
                if self.serial:
                    obj_device.serial = self.serial
                if self.software:
                    obj_device.custom_fields = {'software': self.software}
                    obj_device.save()
                if self.mac_address:
                    obj_device.custom_fields = {'mac': self.mac_address}
                obj_device.save()

                device_record = {obj_device.name: obj_device.id}
                if len(device_record) > 0:
                    self.uuid_device = device_record
                    return self.uuid_device

        if self.role in ["Multi Switch"]:
            if self.stack_swi_num and self.vc_name:
                #Check virtual chassis
                obj_vc = _VirtualChassis(self.vc_name)
                obj_vc.update_db()
                obj_device = Device.objects.get(name=self.device)
                if not obj_device:
                    obj_device = Device(
                        name = self.device,
                        device_type = self.device_type.id,
                        role = DeviceRole.objects.get(name=self.role).id,
                        site = self.site.id,
                        status = "active",
                        virtual_chassis = obj_vc.id,
                        vc_position = self.stack_swi_num,
                        vc_priority = 16 - int(self.stack_swi_num)
                    )

                if obj_device:
                    if self.serial:
                        obj_device.serial = self.serial
                    if self.software:
                        obj_device.custom_fields = {'software': self.software}
                        obj_device.save()
                    if self.mac_address:
                        obj_device.custom_fields = {'mac': self.mac_address}
                        
                    obj_device.save()

                    # set vc master
                    if self.vc_master:
                        obj_vc.master = self.device
                        obj_vc.update_db()


                    device_record = {obj_device.name: obj_device.id}
                    if len(device_record) > 0:
                        self.uuid_device = device_record
                        return self.uuid_device
        raise ValueError(f"{self.device}, can't be created")
    
class Router(_Device):
    def __init__(self, device, site, device_type) -> None:
        super().__init__("Router" , device, site, device_type)

class SwitchNonStack(_Device):
    def __init__(self, device, site, device_type) -> None:
        super().__init__("Access Switch" , device, site, device_type)

class SwitchStack(_Device):
    def __init__(self, device, site, device_type) -> None:
        super().__init__("Multi Switch" , device, site, device_type)

class AccessPoint(_Device):
    def __init__(self, device, site, device_type) -> None:
        super().__init__("Access Point" , device, site, device_type)

class WirelessController(_Device):
    def __init__(self, device, site, device_type) -> None:
        super().__init__("Wireless Controller" , device, site, device_type)

class Firewall(_Device):
    def __init__(self, device, site, device_type) -> None:
        super().__init__("Firewall" , device, site, device_type)

class MerakiMX(_Device):
    def __init__(self, device, site, device_type) -> None:
        super().__init__("Meraki MX" , device, site, device_type)

class MerakiMS(_Device):
    def __init__(self, device, site, device_type) -> None:
        super().__init__("Meraki MS" , device, site, device_type)

class MerakiMR(_Device):
    def __init__(self, device, site, device_type) -> None:
        super().__init__("Meraki MR" , device, site, device_type)


class _DeviceDetect:
    def __init__(self, hostname, site, version) -> None:
        self.hostname = hostname.replace('>', '').replace('#', '').replace('(', '').replace(')', '').upper()
        self.site = site.upper()
        self.version = dict(version)
        self.role = None
        self.os = None
        self.devices = None

        if not isinstance(self.version, dict):
            raise InvalidInputError("version is invalid")
        
        if not isinstance(self.hostname, str):
            raise InvalidInputError("hostname is invalid")
        
        if not isinstance(self.site, str) or len(self.site) != 3:
            raise InvalidInputError("hostname is invalid")
        
        self.detect()

    def detect(self):
        if self.version and self.hostname:
            # Cisco IOS and IOS-XE
            if self.version.get('version', None):
                # router
                if not self.version['version'].get('switch_num', None):
                    self.role = "Router"
                    self.os = self.version['version'].get('os', None)
                    device_detail = {}
                    device_detail[1] = {
                        "device": self.hostname,
                        "site": self.site,
                        "device_type": self.version['version'].get('chassis', self.version['version'].get('rtr_type', 'invalid')),
                        "serial": self.version['version'].get('chassis_sn', None),
                        "software": self.version['version'].get('version', None)
                    }

                    if len(device_detail) > 0:
                        self.devices = device_detail
                
                # Switch 
                if self.version['version'].get('switch_num', None):
                    switches = self.version['version']['switch_num']
                    # Single
                    if len(switches) == 1:
                        self.role = "Access Switch"
                        self.os = self.version['version'].get('os', None)
                        device_detail = {}
                        for switch in switches:
                            loop_data = {
                                "device": self.hostname,
                                "site": self.site,
                                "device_type": switches[switch].get('model_num', switches[switch].get('model', 'invalid')),
                                "mac_address": switches[switch].get('mac_address', None),
                                "serial": switches[switch].get('system_sn', None),
                                "software": self.version['version'].get('version', None),
                                "swi_num": int(switch)
                            }
                            device_detail[1] = loop_data

                        if len(device_detail) > 0:
                            self.devices = device_detail
                    # Stacked Switch
                    if len(switches) >= 2:
                        self.role = "Multi Switch"
                        self.os = self.version['version'].get('os', None)
                        switch_num = list(switches)
                        switch_num = [int(i) for i in switch_num]
                        switch_num.sort()
                        master_swi = switch_num[0]

                        device_detail = {}
                        for switch in switches:
                            # for switches without any model information
                            if not switches[switch].get('model_num', None) and not switches[switch].get('model', None):
                                loop_data = {
                                    "device": f"{self.hostname}_{switch}",
                                    "site": self.site,
                                    "device_type": self.version['version'].get('chassis', self.version['version'].get('rtr_type', 'Invalid')),
                                    "mac_address": None,
                                    "serial": None,
                                    "software": self.version['version'].get('version', None),
                                    "swi_num": int(switch),
                                    "vc_master": True if master_swi == int(switch) else False,
                                    "vc_name": self.hostname
                                }
                            if switches[switch].get('model_num', None) or switches[switch].get('model', None):
                                loop_data = {
                                    "device": f"{self.hostname}_{switch}",
                                    "site": self.site,
                                    "device_type": switches[switch].get('model_num', switches[switch].get('model', 'invalid')),
                                    "mac_address": switches[switch].get('mac_address', None),
                                    "serial": switches[switch].get('system_sn', None),
                                    "software": self.version['version'].get('version', None),
                                    "swi_num": int(switch),
                                    "vc_master": True if master_swi == int(switch) else False,
                                    "vc_name": self.hostname
                                }
                            device_detail[int(switch)] = loop_data
                        
                        if len(device_detail) > 0:
                            self.devices = device_detail
            
            # Cisco Nexus
            if self.version.get('platform', None):
                pass


class FixInterfacesName:
    def __init__(self, device, position) -> None:
        self.device_id = Device.objects.get(name=device).id
        self.position = int(position)
        self.name_fixed = False

        obj_interfaces = Interface.objects.filter(device_id=self.device_id)
        if not obj_interfaces:
            raise ValueError(f"device: {device} has no interfaces")
        
        if not self.position:
            raise ValueError(f"Switch position value empty")
        
        for interface in obj_interfaces:
            new_name = name_fix(text=interface.name, position=self.position)
            if new_name:
                interface.name = new_name
                interface.save()
                self.name_fixed = True

class MissingInterfaces:
    def __init__(self, all_interfaces: dict) -> None:
        """
        all_interfaces structure: {'device': [interface]}
        """
        self.all_interfaces = all_interfaces
        self.interface_created = None

        if not isinstance(self.all_interfaces, dict):
            raise InvalidInputError("all_interfaces is invalid")
        
        self.fix_missing_interface()
    
    def fix_missing_interface(self) -> None:
        result_dict = {}
        for device in self.all_interfaces:
            loop_list = []
            # Fetch all interfaces of current device
            current_device_interfaces = {}
            device_id = Device.objects.get(name=device).id
            obj_interfaces = Interface.objects.filter(device_id=device_id)
            if obj_interfaces:
                for i in obj_interfaces:
                    current_device_interfaces[i.name] = i.id
            
            # Checking interfaces of input data
            interfaces = self.all_interfaces[device]
            if isinstance(interfaces, list) and len(interfaces) > 0:
                #Checking for missing interface
                for interface in interfaces:
                    if not current_device_interfaces.get(interface, None):
                        obj_interface = Interface(
                            device = device_id,
                            name = interface,
                            type = "virtual" if interface.lower().startswith("loopback") or interface.lower().startswith("vlan") or "." in interface else "10gbase-x-x2",
                            enabled = True
                        )
                        if obj_interface:
                            loop_list.append({interface: obj_interface.id})
            if len(loop_list) > 0:
                result_dict[device] = loop_list
        if len(result_dict) > 0:
            self.interface_created = result_dict
                    

def name_fix(text, position):
    if position > 1:
        regex = r"(\D*)(\d+)/(\d+)/(\d+)"
        match = re.match(pattern=regex, string=text)
        if match:
            if int(position) != int(match.group(2)):
                return f"{match.group(1)}{position}/{match.group(3)}/{match.group(4)}"
    return None

def switch_number_interface(interface):
    regex = r"(\D*)(\d+)/(\d+)/(\d+)"
    match = re.match(pattern=regex, string=interface)
    if match:
        return int(match.group(2))
    
    if not match:
        regex = r"(\D*)(\d+)/(\d+)"
        match = re.match(pattern=regex, string=interface)
        if match:
            return int(match.group(2))
    
    return None



def find_network_module(data, keyword, path=None, output_dict=None):
    if path is None:
        path = []
    if output_dict is None:
        output_dict = {}
    try:
        for k, v in data.items():
            current_path = path + [k]
            if isinstance(v, dict):
                find_network_module(v, keyword, current_path, output_dict)
            elif k == "name" and isinstance(v, str):  # Check if key is 'name'
                if keyword.lower() in v.lower():
                    parent_dict = data
                    if "name" in parent_dict and "pid" in parent_dict:
                        # path_str = "_".join(path) if path else k # create path string
                        current_output = output_dict
                        for key in path[
                            :-1
                        ]:  # Exclude the last key (which is 'name') from path traversal
                            if key not in current_output:
                                current_output[key] = {}
                            current_output = current_output[key]

                        if (
                            path and path[-2] == "rp"
                        ):  # Check if the key before 'name' is 'rp'
                            current_output[parent_dict["pid"]] = (
                                {  # Directly assign to 'rp' key
                                    "name": parent_dict["name"],
                                    "descr": parent_dict["descr"],
                                    "pid": parent_dict["pid"],
                                    "sn": parent_dict["sn"],
                                }
                            )
                        else:
                            current_output[path[-2]] = (
                                {  # Use the key before 'name' as key in output
                                    parent_dict[
                                        "pid"
                                    ]: {  # Keep pid level if not under 'rp' - although this might not be needed based on 'remove 2 levels after rp' which is likely simplification to remove 1 level
                                        "name": parent_dict["name"],
                                        "descr": parent_dict["descr"],
                                        "pid": parent_dict["pid"],
                                        "sn": parent_dict["sn"],
                                    }
                                }
                            )
    except:
        pass
    
    finally:
        if len(output_dict) == 0:
            return None
        return output_dict




class _Inventory:
    def __init__(self, module_bay, device, module_type) -> None:
        self.module_bay = module_bay
        self.module_bay_id = None
        self.device_id = Device.objects.get(name=device).id
        self.module_type_id = ModuleType.objects.get(part_number=module_type).id
        self.serial = None
        self.description = None
        self.uuid_module = None

        # update bay
        self.locate_bay()
    
    def locate_bay(self) -> None:
        if self.device_id:
            if self.module_bay == "Network Module":
                obj_module_bay = ModuleBay.objects.get(device_id=self.device_id, name="Network Module")
                if not obj_module_bay:
                    raise ValueError(f"Device id: {self.device_id}, no module bay exist")
                if obj_module_bay:
                    self.module_bay_id = obj_module_bay.id

            if self.module_bay == "Fan":
                pass
    
    def attach_module(self) -> None:
        if self.device_id and self.module_bay_id and self.module_type_id:
            obj_module = Module.objects.get(device_id=self.device_id, module_bay_id=self.module_bay_id)
            if not obj_module:
                obj_module = Module(
                    device = self.device_id,
                    module_bay = self.module_bay_id,
                    module_type = self.module_type_id,
                    status = "active"
                )
            
            if obj_module:
                # update serial and description
                if self.serial:
                    obj_module.serial = self.serial
                if self.description:
                    obj_module.description = self.description
                obj_module.save()
                self.uuid_module = obj_module.id
                

class NetworkModule(_Inventory):
    def __init__(self, device, module_type) -> None:
        super().__init__("Network Module", device, module_type)


class _IPAM:
    def __init__(self, ip_addr_interface) -> None:
        self.ip_addr_interface = ip_addr_interface
        self.uuid_ip_address = None
        self.uuid_interfaces = None
        self.stop_process = False
    
    def create_ip_address(self) -> None:
        if not isinstance(self.ip_addr_interface, list) or len(self.ip_addr_interface) < 0:
            raise InvalidInputError("ip_address list value not provided")

        loop_ip = {}
        for ip in self.ip_addr_interface:
            if ip.get('oper_status', 'down') == 'up' and ip.get('ip_addr', None):
                obj_ip_addr = IPAddress.objects.get(address=ip['ip_addr'])
                if obj_ip_addr:
                    loop_ip[ip['ip_addr']] = obj_ip_addr.id
                
                if not obj_ip_addr:
                    try:
                        netbox_ip = IPAddress(
                            address = ip['ip_addr'],
                            status = "active"
                        )
                        if netbox_ip:
                            loop_ip[ip['ip_addr']] = netbox_ip.id
                    except:
                        print(f"{ip['ip_addr']} - Duplicate IP address found in global table")
            
        # assign loop_ip to uuid_ip_address if there is some data in it
        if len(loop_ip) > 0:
            self.uuid_ip_address = loop_ip
    
    def map_ip_interface(self) -> None:
        """
        input [{'device': 'device_name', 'interface': 'interface_name', 'ip_addr': 'x.x.x.x/xx'}]
        """
        if not isinstance(self.ip_addr_interface, list) or not len(self.ip_addr_interface) > 0:
            raise InvalidInputError("ip_address list value not provided")
        
        loop_interfaces = {}
        for item in self.ip_addr_interface:
            if item.get('oper_status', 'down') == 'up' and item.get('ip_addr', None):
                obj_port = Interface.objects.get(device=item['device'], name=item['interface'])
                obj_ip_addr = IPAddress.objects.get(address=item['ip_addr'])
                if not obj_port:
                    obj_device = Device.objects.get(name=item['device'])
                    if obj_device:
                        obj_port = Interface(
                            device = obj_device.id,
                            name = item['interface'],
                            type = "virtual",
                            enabled = True
                        )
                if not obj_ip_addr:
                    try:
                        obj_ip_addr = IPAddress(
                            address = item['ip_addr'],
                            status = "active"
                            )
                    except:
                        print(f"{item['ip_addr']} - Duplicate IP address, assign to port failed")
                if obj_port and obj_ip_addr:
                # mapping interface to ip address
                    obj_ip_addr.assigned_object = obj_port
                    obj_ip_addr.assigned_object_id = obj_port.id
                    obj_ip_addr.assigned_object_type = 'dcim.interface'
                    obj_ip_addr.save()
                            
                    loop_interfaces[item['ip_addr']] = obj_port.id
        
        # assign loop_interface to uuid_interfaces if there is some data in it
        if len(loop_interfaces) > 0:
            self.uuid_interfaces = loop_interfaces
    
    def update_primary_ip(self, device, primary_ip) -> bool:
        obj_ip_addr = IPAddress.objects.get(address=primary_ip, assigned=True, device=device)
        obj_device = Device.objects.get(name=device)
        if obj_ip_addr and obj_device:
            obj_device.primary_ip4 = obj_ip_addr.id
            obj_device.save()
            return True
        return False





    

class _VirtualChassis:
    def __init__(self, hostname) -> None:
        self.vc_name = hostname.upper()
        self.master = None
        self.id = None
        self.flag_vc_presence = None

        # Checking if VC exist or not
        obj_vc = VirtualChassis.objects.get(name=self.vc_name)
        if obj_vc:
            self.flag_vc_presence = True
            if obj_vc.master:
                self.master = obj_vc.master.name
    
    def update_db(self):
        obj_vc = VirtualChassis.objects.get(name=self.vc_name)
        if not obj_vc:
            obj_vc = VirtualChassis(
                name = self.vc_name.upper()
            )
        
        if obj_vc:
            if self.master:
                obj_vc.master = Device.objects.get(name=self.master).id
                obj_vc.save()
            self.id = obj_vc.id



class Onboarding:
    def __init__(self, hostname, site, version, interfaces, inventory) -> None:
        self.hostname = hostname
        self.site = site
        self.version = version
        self.interfaces = interfaces
        self.inventory = inventory
        self.stack_ports_summary = None
        self.stack_ports_connection = None
        self.cdp_neighbors_detail = None
        self.cdp_neighbors_connection = None
        self.tacacs_ip = None
        self.tacacs_device = None
        self.flag_primary_ip = False
        self.os = None
        self.role = None
        self.devices = None
        self.ip_addr_interface = None
        self.all_interfaces = None
        self.all_modules = None
        self.onboard_complete = None

        if not self.hostname:
            raise InvalidInputError("hostname value missing")
        if not self.site:
            raise InvalidInputError("site value missing")
        if not self.version:
            raise InvalidInputError("site value missing")
        if not self.interfaces:
            raise InvalidInputError("interfaces value missing")
        if not self.inventory:
            raise InvalidInputError("inventory value missing")

    def identify_device(self) -> None:    
        #Finding OS and device category
        obj_detect = _DeviceDetect(hostname=self.hostname, site=self.site, version=self.version)
        if obj_detect:
            self.os = obj_detect.os
            self.role = obj_detect.role
            self.devices = obj_detect.devices
    
    def identify_ip_prefix(self) -> None:
        # build list of ip address and ip with interfaces
        """
        required format: [{'device': 'device_name', 'interface': 'interface_name', 'ip_addr': 'x.x.x.x/xx'}]
        """
        if self.role in ['Router', 'Access Switch']:
            loop_ip_intf = []
            for interface in self.interfaces:
                
                if interface.startswith("Mgm") or interface.startswith("mgm") or interface.startswith("Gig") or interface.startswith("Eth") or interface.startswith("Fa") or interface.startswith("Tw") or interface.startswith("Te") or interface.startswith("Serial") or interface.startswith("Hu") or interface.startswith("Loop") or interface.startswith("loop") or interface.startswith("Vlan") or interface.startswith("Fo"):

                    tmp_data = {
                                'device': self.devices[1]['device'],
                                'interface': interface,
                                'oper_status': self.interfaces[interface].get('oper_status', 'down'),
                                }
                    
                    ipv4 = self.interfaces[interface].get('ipv4', None)
                    if ipv4:
                        for ip in ipv4:
                            if not ip.startswith("192.168.") and not ip.startswith("169."):
                                tmp_data['ip_addr'] = ip

                    loop_ip_intf.append(tmp_data)

                    # set tacacs device
                    self.tacacs_device = self.devices[1]['device']

            # assign loop_ip_intf to ip_addr_interface if list is not blank
            if len(loop_ip_intf) > 0:
                self.ip_addr_interface = loop_ip_intf

        if self.role in ['Multi Switch']:
            # set master switch for all logical ports
            stack_master = None
            for switch in self.devices:
                if self.devices[switch].get('vc_master'):
                    stack_master = f"{self.devices[switch]['device']}"
                    # set tacacs device
                    self.tacacs_device = stack_master
            
            #raise error if stack master is None
            if not stack_master:
                raise ValueError(f"{self.hostname}: don't have any stack master")

            loop_ip_intf = []
            for interface in self.interfaces:
                
                # Physical interfaces
                if interface.startswith("Mgm") or interface.startswith("mgm") or interface.startswith("Gig") or interface.startswith("Eth") or interface.startswith("Fa") or interface.startswith("Tw") or interface.startswith("Te") or interface.startswith("Serial") or interface.startswith("Hu") or interface.startswith("Fo"):

                    swi_num = switch_number_interface(interface)
                    ipv4 = self.interfaces[interface].get('ipv4', None)

                    tmp_data = {
                            'interface': interface,
                            'oper_status': self.interfaces[interface].get('oper_status', 'down'),
                            }
                    
                    if ipv4:
                        for ip in ipv4:
                            if not ip.startswith("192.168.") and not ip.startswith("169."):
                                tmp_data['ip_addr'] = ip

                    if swi_num and self.devices.get(swi_num, None) and self.devices[swi_num]['device']:
                        tmp_data['device'] = self.devices[swi_num]['device']
                        loop_ip_intf.append(tmp_data)
                    
                    if not swi_num:
                        tmp_data['device'] = stack_master
                
                # Logical interfaces
                if interface.startswith("Vlan") or interface.startswith("Loop") or interface.startswith("loop"):
                    ipv4 = self.interfaces[interface].get('ipv4', None)

                    tmp_data = {
                            'device': stack_master,
                            'interface': interface,
                            'oper_status': self.interfaces[interface].get('oper_status', 'down'),
                            }
                    
                    if ipv4:
                        for ip in ipv4:
                            for ip in ipv4:
                                if not ip.startswith("192.168.") and not ip.startswith("169."):
                                    tmp_data['ip_addr'] = ip
                        
                    loop_ip_intf.append(tmp_data)

            # assign loop_ip_intf to ip_addr_interface if list is not blank
            if len(loop_ip_intf) > 0:
                self.ip_addr_interface = loop_ip_intf
    
    def identify_interfaces(self) -> None:
        if not self.ip_addr_interface:
            raise ValueError("ip_addr_interface is missing")
        
        all_interfaces = {}
        for device in self.devices:
            current_intf = []
            current_device = self.devices[device]['device']

            for interface in self.ip_addr_interface:
                if interface['device'] == current_device:
                    current_intf.append(interface['interface'])
            
            if len(current_intf) > 0:
                all_interfaces[current_device] = current_intf
        
        if len(all_interfaces) > 0:
            self.all_interfaces = all_interfaces

    def identify_inventory(self) -> None:
        """
        output format: {'device': 'SSK-7-SWI-01_1','module_type': 'C9300-NM-2Y', 'serial': 'ABCD-EFGH-IJKL-GHJK', 'description': '2x25G Uplink Module'}
        """
        uplink_module = find_network_module(data=self.inventory, keyword="Uplink Module")
        if isinstance(uplink_module, dict):
            if self.role in ['Router', 'Access Switch']:
                all_modules = []
                slots = uplink_module.get('slot', None)
                if slots:
                    for slot in slots:
                        modules = slots[slot].get('rp', None)
                        if modules:
                            for module in modules:
                                dict_loop = {
                                    'device': self.devices[1]['device'],
                                    'module_type': module,
                                    'serial': modules[module].get('sn', None),
                                    'description': modules[module].get('descr', None)
                                }
                                all_modules.append(dict_loop)
                    if len(all_modules) > 0:
                        self.all_modules = all_modules
            
            if self.role in ['Multi Switch']:
                all_modules = []
                slots = uplink_module.get('slot', None)
                if slots:
                    for slot in slots:
                        modules = slots[slot].get('rp', None)
                        if modules:
                            for module in modules:
                                dict_loop = {
                                    'device': self.devices[int(slot)]['device'],
                                    'module_type': module,
                                    'serial': modules[module].get('sn', None),
                                    'description': modules[module].get('descr', None)
                                }
                                all_modules.append(dict_loop)
                    if len(all_modules) > 0:
                        self.all_modules = all_modules

    def identify_tacacs_ip(self):
        if self.tacacs_device:
            if self.tacacs_ip:
                #check for device in self.ip_addr_interface
                for interface in self.ip_addr_interface:
                    if interface.get('ip_addr', None) and interface.get('oper_status', 'down') == 'up':
                        ip = interface['ip_addr'].split('/')[0]
                        if ip == self.tacacs:
                            #call funct update_primary_ip
                            print(f'{self.tacacs_ip}: tacacs ip matched, device: {self.tacacs_device}')
                            self.flag_primary_ip = True
                            return

            if not self.tacacs_ip:
                #priority: loopback interface
                for interface in self.ip_addr_interface:
                    if interface['interface'].startswith('Loopback') or interface['interface'].startswith('loopback'):
                        if interface.get('ip_addr', None) and interface.get('oper_status', 'down') == 'up':
                            #call funct update_primary_ip
                            self.tacacs_ip = interface['ip_addr']
                            print(f'{self.tacacs_ip}: tacacs ip matched, device: {self.tacacs_device}')
                            self.flag_primary_ip = True
                            return
                
                #priority: Mgmt interface
                for interface in self.ip_addr_interface:
                    if interface['interface'].startswith('Mgmt') or interface['interface'].startswith('mgmt'):
                        if interface.get('ip_addr', None) and interface.get('oper_status', 'down') == 'up':
                            #call funct update_primary_ip
                            self.tacacs_ip = interface['ip_addr']
                            print(f'{self.tacacs_ip}: tacacs ip matched, device: {self.tacacs_device}')
                            self.flag_primary_ip = True
                            return
                
                #priority: Vlan interface
                for interface in self.ip_addr_interface:
                    if interface['interface'].startswith('Vlan') or interface['interface'].startswith('vlan'):
                        if interface.get('ip_addr', None) and interface.get('oper_status', 'down') == 'up':
                            #call funct update_primary_ip
                            self.tacacs_ip = interface['ip_addr']
                            print(f'{self.tacacs_ip}: tacacs ip matched, device: {self.tacacs_device}')
                            self.flag_primary_ip = True
                            return
                
                #priority: Physical interface
                for interface in self.ip_addr_interface:
                    if (interface['interface'].startswith('Eth') or interface['interface'].startswith('Fa') or interface['interface'].startswith('Gi')
                        or interface['interface'].startswith('Tw') or interface['interface'].startswith('Te') or interface['interface'].startswith('Hu')):

                        if interface.get('ip_addr', None) and interface.get('oper_status', 'down') == 'up':
                            #call funct update_primary_ip
                            self.tacacs_ip = interface['ip_addr']
                            print(f'{self.tacacs_ip}: tacacs ip matched, device: {self.tacacs_device}')
                            self.flag_primary_ip = True
                            return

    def identify_adjacency(self) -> None:
        if self.stack_ports_summary:
            """
            furure implementation
            """
            pass

        if self.cdp_neighbors_detail:
            obj_adjacency = AdjacencyNormal(hostname=self.hostname, adjacency_table=self.cdp_neighbors_detail)
            if obj_adjacency.connection_records:
                self.cdp_neighbors_connection = obj_adjacency.connection_records


    def execute_task1(self):
        """
        Add/Update Device
        """
        if not self.devices:
            raise ValueError(f"{self.hostname}: failed to gather basic details")
        
        # Task 1 : add or update device
        if self.role == "Router":
            obj_router = Router(device=self.devices[1]['device'], site=self.devices[1]['site'], device_type=self.devices[1]['device_type'])
            obj_router.serial = self.devices[1].get('serial', None)
            obj_router.software = self.devices[1].get('software', None)
            result = obj_router.update_db()
            if result:
                print(f"{self.devices[1]['device']}, created")
            if not result:
                raise DeviceCreateError(f"{self.devices[1]['device']}, creation failed")
        
        if self.role == "Access Switch":
            obj_switch = SwitchNonStack(device=self.devices[1]['device'], site=self.devices[1]['site'], device_type=self.devices[1]['device_type'])
            obj_switch.serial = self.devices[1].get('serial', None)
            obj_switch.mac_address = self.devices[1].get('mac_address', None)
            obj_switch.software = self.devices[1].get('software', None)
            result = obj_switch.update_db()
            if result:
                print(f"{self.devices[1]['device']}, created")
            if not result:
                raise DeviceCreateError(f"{self.devices[1]['device']}, creation failed")
        
        if self.role == "Multi Switch":

            for item in self.devices:
                obj_switch = SwitchStack(device=self.devices[item]['device'], site=self.devices[item]['site'], device_type=self.devices[item]['device_type'])
                obj_switch.serial = self.devices[item].get('serial', None)
                obj_switch.mac_address = self.devices[item].get('mac_address', None)
                obj_switch.software = self.devices[item].get('software', None)
                obj_switch.vc_master = self.devices[item].get('vc_master', None)
                obj_switch.vc_name = self.devices[item].get('vc_name', None)
                obj_switch.stack_swi_num = self.devices[item].get('swi_num', None)
                
                if not obj_switch.vc_name or not obj_switch.stack_swi_num:
                    raise DeviceCreateError(f"{self.devices[1]['device']}, creation failed, reason: vc_name or swi_num missing")
                result = obj_switch.update_db()
                if result:
                    print(f"{self.devices[item]['device']}: record updated")
                if not result:
                    raise DeviceCreateError(f"{self.devices[item]['device']}: record failed")
    
    def execute_task1_1(self):
        """
        Enable master switch in stack
        """
        if self.role == "Multi Switch":
           for switch in self.devices:
               if self.devices[switch].get('vc_master', False) and self.devices[switch].get('vc_name', None):
                   obj_vc = _VirtualChassis(hostname=self.hostname)
                   obj_vc.master = self.devices[switch]['device']
                   obj_vc.update_db()
                   if obj_vc.id:
                       print(f"{self.devices[switch]['device']} is now master in stack")
                

    def execute_task2(self):
        """
        Uplink module
        """
        if not self.all_modules:
            print(f"{self.hostname}: no uplink module found")
        
        if self.all_modules:
            for module in self.all_modules:
                obj_nm_module = NetworkModule(device=module['device'], module_type=module['module_type'])
                obj_nm_module.serial = module['serial']
                obj_nm_module.description = module['description']
                obj_nm_module.attach_module()
                if obj_nm_module.uuid_module:
                    print(f"{module['device']}: uplink module:{module['module_type']} attached")
                
                if not obj_nm_module.uuid_module:
                    print(f"{module['device']}: uplink module:{module['module_type']} failed to attach")
    
    def execute_task3(self):
        """
        Interface name fix
        """
        if self.role in ["Access Switch", "Multi Switch"]:
            for item in self.devices:
                try:
                    obj_switch = FixInterfacesName(device=self.devices[item]['device'], position=self.devices[item]['swi_num'])
                    if obj_switch.name_fixed:
                        print(f"{self.devices[item]['device']}: interface name fixed")
                except ValueError:
                    print(f"{self.devices[item]['device']} has no interfaces")

    def execute_task4(self):
        """
        create all missing interfaces
        """
        if not self.all_interfaces:
            raise ValueError(f"{self.hostname}: all_interfaces is missing")
        
        obj_missing_intf = MissingInterfaces(all_interfaces=self.all_interfaces)
        if obj_missing_intf.interface_created:
            print(f"{self.hostname}: missing interface created")
        if not obj_missing_intf.interface_created:
            print(f"{self.hostname}: interface not created")
    
    def execute_task5(self):
        """
        IP address create and IP interface mapping, set primary ip
        """
        if not self.ip_addr_interface:
            raise ValueError(f"{self.hostname}: no ip addresses found")
        
        obj_ipam = _IPAM(ip_addr_interface=self.ip_addr_interface)
        obj_ipam.create_ip_address()
        if obj_ipam.uuid_ip_address:
            print(f"{self.hostname}: ip addresses created")
            obj_ipam.map_ip_interface()
            if obj_ipam.uuid_interfaces:
                print(f"{self.hostname}: ip addresses mapped with interfaces")
        
        # set primary ip
        if self.flag_primary_ip and self.tacacs_device and self.tacacs_ip:
            obj_ipam.update_primary_ip(device=self.tacacs_device, primary_ip=self.tacacs_ip)
        if self.flag_primary_ip:
            print(f"{self.hostname}: primary ip enabled")
        if not self.flag_primary_ip:
            print(f"{self.hostname}: primary ip failed to enable")
    
    def execute_task6(self):
        """
        Cable connection
        """
        if self.stack_ports_connection:
            """
            Future feature
            """
            pass

        if self.cdp_neighbors_connection:
            for conn in self.cdp_neighbors_connection:
                try:
                    obj_connection = Connection(a_device=conn['a_device'], a_port=conn['a_port'],
                                            b_device=conn['b_device'], b_port=conn['b_port'])
                
                    conn_status = obj_connection.make_connection()
                    if conn_status:
                        print(f"{conn['a_device']}:{conn['a_port']} --> {conn['b_device']}:{conn['b_port']} cable connected ")
                except ValueError:
                    print(f"remote device: {conn['b_device']} has no port {conn['b_port']}")
                    
    
    def automatic(self):

        # Collecting data
        """ tacacs ip can be defined """
        self.identify_device()
        self.identify_ip_prefix()
        self.identify_interfaces()
        self.identify_inventory()
        self.identify_tacacs_ip()
        self.identify_adjacency()

        # execution
        self.execute_task1()
        self.execute_task1_1()
        self.execute_task2()
        self.execute_task3()
        self.execute_task4()
        self.execute_task5()
        self.execute_task6()

        print(f"{self.hostname}: onboard complete")


