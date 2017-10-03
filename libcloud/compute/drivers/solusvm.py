import json
import socket
import time
from libcloud.compute.base import (Node, NodeDriver, NodeState)
from libcloud.common.solusvm import SolusVMConnection
from libcloud.utils.networking import is_public_subnet
from libcloud.compute.providers import Provider

__all__ = [
    "SolusVMNodeDriver"
]

API_VERSION = '1.0'


class SolusVMNodeDriver(NodeDriver):
    """
    Base SolusVM node driver.
    """

    connectionCls = SolusVMConnection
    type = Provider.SOLUSVM
    name = 'SolusVM'
    website = 'http://solusvm.com/'

    def __init__(self, key=None, secret=None,
                 host='solusvm.com', port=None,
                 verify=True
                 ):
        """
        :param key: username
        :param secret: password
        :param host: solusvm host
        :param port: solusvm host port
        """
        if not key or not secret:
            raise Exception("Key and secret not specified")

        secure = True if host.startswith('https://') else False

        if not port:
            port = 443 if host.startswith('https://') else 80

        # strip the prefix
        prefixes = ['http://', 'https://']
        for prefix in prefixes:
            if host.startswith(prefix):
                host = host.replace(prefix, '')
        host = host.split('/')[0]

        super(SolusVMNodeDriver, self).__init__(key=key,
                                                secret=secret,
                                                host=host,
                                                port=port,
                                                secure=secure)

        self.connection.secure = secure

        self.connection.host = host
        self.connection.port = port

        try:
            socket.setdefaulttimeout(15)
            so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            so.connect((host, int(port)))
            so.close()
        except:
            raise Exception("Make sure solusvm host is accessible and port "
                            "%s is open" % port)
        # do not verify SSL certificate
        if not verify:
            self.connection.connection.ca_cert = False

    def create_node(self, vttype='openvz', user_id=31, nodegroup_id=1,
                    hostname='', vmos='', vmostpl='', diskspace=1,
                    ram=128, burst=128, ipv4=1, ipv6=0, bandwidth=1, isos=""):
        """
        Add a VS
        """

        server_params = dict(
            vttype=vttype,
            user_id=user_id,
            nodegroup_id=nodegroup_id,
            hostname=hostname,
            vmos=vmos,
            vmostpl=vmostpl,
            diskspace=diskspace,
            ram=ram,
            burst=burst,
            ipv4=ipv4,
            ipv6=ipv6,
            bandwidth=bandwidth,
            isos=isos,
        )
        data = json.dumps({"virtual_machine": server_params})

        # upon successfull machine creation,
        # response is 201 with empty body
        # attempting to return the real node
        existing_nodes = self.list_nodes()
        try:
            self.connection.request(
                "/api/v%s/servers" % API_VERSION,
                data=data,
                headers={
                    "Content-type": "application/json"},
                method="POST")
        except Exception as exc:
            raise Exception("Failed to create node: %s" % exc)

        new_node = None
        for i in range(0, 10):
            nodes = self.list_nodes()
            for node in nodes:
                if node.id not in [n.id for n in existing_nodes] and \
                   node.name == hostname:
                        new_node = node
                        return new_node
            time.sleep(10)

    def ex_start_node(self, node):
        """
        Start a node
        """
        action = "/api/v%s/servers/%s/boot" % (
            API_VERSION, node.id)

        result = self.connection.request(action, method="POST")
        return True if result.status == 201 else False

    def ex_stop_node(self, node):
        """
        Stop a node
        """
        action = "/api/v%s/servers/%s/shutdown" % (
            API_VERSION, node.id)

        result = self.connection.request(action, method="POST")
        return True if result.status == 201 else False

    def reboot_node(self, node):
        """
        Reboot a node
        """
        action = "/api/v%s/servers/%s/reboot" % (
            API_VERSION, node.id)

        result = self.connection.request(action, method="POST")
        return True if result.status == 201 else False

    def destroy_node(self, node):
        """
        Delete a VS
        """
        action = "/api/v%s/servers/%s" % (
            API_VERSION, node.id)

        self.connection.request(action, method="DELETE")
        return True

    def list_nodes(self):
        """
        List all VS

        :rtype: ``list`` of :class:`SolusVMNode`
        """
        response = self.connection.request("/api/v%s/servers" %
                                           API_VERSION)
        nodes = [self._to_node(vm["server"])
                 for vm in response.object]
        return nodes

    def ex_list_a_vs_parameter(self, vttype):
        """
        Get List of VS Parameters for a Virtualization Type

        vttype can be one of openvz, xen, xenhvm, kvm

        """
        response = self.connection.request("/api/v%s/servers/"
                                           "createvm_params/%s" %
                                           (API_VERSION, vttype))
        return response.object

    def ex_list_vs_parameters(self):
        """
        Get List of VS Parameters for Virtualization Types

        """
        vs_parameters = []
        for vttype in ['openvz', 'kvm', 'xen', 'xenhvm']:
            try:
                params = self.ex_list_a_vs_parameter(vttype)
                vs_parameters.append(params)
            except:
                # Virtualization Type not supported
                pass

        return vs_parameters

    def ex_list_users(self):
        """
        Get List of users, if user is Reseller

        """
        ret = {}
        try:
            response = self.connection.request("/api/v%s/users" % API_VERSION)
            ret['reseller'] = True
            ret['list_of_users'] = response.object
        except:
            ret['reseller'] = False

        return ret

    def _to_node(self, data):
        identifier = data['id']
        name = data['hostname']
        private_ips = []
        public_ips = []
        mainipaddress = data.get('mainipaddress')
        ipaddresses = data.get('ipaddresses')
        all_ips = [mainipaddress]
        if ipaddresses and isinstance(ipaddresses, basestring):
            all_ips.append(ipaddresses)
        if ipaddresses and isinstance(ipaddresses, list):
            all_ips.extend(ipaddresses)
        for ip in all_ips:
            try:
                if is_public_subnet(ip):
                    if ip not in public_ips:
                        public_ips.append(ip)
                else:
                    if ip not in private_ips:
                        private_ips.append(ip)
            except:
                # IPV6 not supported
                pass
        extra = {}
        extra['creationdate'] = data.get('creationdate')
        extra['clientid'] = data.get('clientid')
        extra['consoleusername'] = data.get('consoleusername')
        extra['hostname'] = data.get('hostname')
        extra['os'] = data.get('templatename')
        extra['type'] = data.get('type')
        extra['disk'] = data.get('disk')
        extra['memory'] = data.get('ram')
        extra['bandwidth'] = data.get('freebandwidth')
        if data.get('template'):
            extra['image'] = data.get('template')
        status = data.get('status')
        if status == 'online':
            state = NodeState.RUNNING
        elif status == 'offline':
            state = NodeState.STOPPED
        else:
            state = NodeState.UNKNOWN

        return Node(identifier,
                    name,
                    state,
                    public_ips,
                    private_ips,
                    self,
                    extra=extra)
