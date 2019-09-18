# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Node driver for Tencent.
"""

try:
    import simplejson as json
except ImportError:
    import json
import time
import base64
import hashlib

from libcloud.common.tencent import TencentHTTPResponse, SignedTencentConnection
from libcloud.common.types import LibcloudError
from libcloud.compute.base import Node, NodeDriver, NodeImage, NodeSize, \
    StorageVolume, VolumeSnapshot, NodeLocation, KeyPair
from libcloud.compute.types import NodeState, StorageVolumeState, \
    VolumeSnapshotState
from libcloud.utils.py3 import _real_unicode as u
from libcloud.utils.py3 import ensure_string, b
from libcloud.utils.xml import findall, findattr, findtext
from libcloud.utils.publickey import get_pubkey_ssh2_fingerprint
from libcloud.utils.publickey import get_pubkey_comment

from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.cvm.v20170312 import cvm_client, models
from tencentcloud.cbs.v20170312 import cbs_client
from tencentcloud.cbs.v20170312 import models as cbs_models
from tencentcloud.vpc.v20170312 import vpc_client
from tencentcloud.vpc.v20170312 import models as vpc_models

__all__ = [
    'DiskCategory', 'InternetChargeType', 'CVM_API_VERSION', 'CVMDriver',
    'CVMSecurityGroup', 'CVMZone'
]

CVM_API_VERSION = '2017-03-12'
CVM_API_ENDPOINT = 'cvm.tencentcloudapi.com'
DEFAULT_SIGNATURE_VERSION = '1.0'


def _parse_bool(value):
    if isinstance(value, bool):
        return value
    if u(value).lower() == 'true':
        return True
    return False


"""
Define the extra dictionary for specific resources
"""
RESOURCE_EXTRA_ATTRIBUTES_MAP = {
    'node': {
        'description': {
            'xpath': 'Description',
            'transform_func': u
        },
        'image_id': {
            'xpath': 'ImageId',
            'transform_func': u
        },
        'zone_id': {
            'xpath': 'ZoneId',
            'transform_func': u
        },
        'instance_type': {
            'xpath': 'InstanceType',
            'transform_func': u
        },
        'instance_type_family': {
            'xpath': 'InstanceTypeFamily',
            'transform_func': u
        },
        'hostname': {
            'xpath': 'HostName',
            'transform_func': u
        },
        'serial_number': {
            'xpath': 'SerialNumber',
            'transform_func': u
        },
        'internet_charge_type': {
            'xpath': 'InternetChargeType',
            'transform_func': u
        },
        'creation_time': {
            'xpath': 'CreationTime',
            'transform_func': u
        },
        'instance_network_type': {
            'xpath': 'InstanceNetworkType',
            'transform_func': u
        },
        'instance_charge_type': {
            'xpath': 'InstanceChargeType',
            'transform_func': u
        },
        'device_available': {
            'xpath': 'DeviceAvailable',
            'transform_func': u
        },
        'io_optimized': {
            'xpath': 'IoOptimized',
            'transform_func': u
        },
        'expired_time': {
            'xpath': 'ExpiredTime',
            'transform_func': u
        }
    },
    'vpc_attributes': {
        'vpc_id': {
            'xpath': 'VpcId',
            'transform_func': u
        },
        'vswitch_id': {
            'xpath': 'VSwitchId',
            'transform_func': u
        },
        'private_ip_address': {
            'xpath': 'PrivateIpAddress/IpAddress',
            'transform_func': u
        },
        'nat_ip_address': {
            'xpath': 'NatIpAddress',
            'transform_func': u
        }
    },
    'eip_address_associate': {
        'allocation_id': {
            'xpath': 'AllocationId',
            'transform_func': u
        },
        'ip_address': {
            'xpath': 'IpAddress',
            'transform_func': u
        },
        'bandwidth': {
            'xpath': 'Bandwidth',
            'transform_func': int
        },
        'internet_charge_type': {
            'xpath': 'InternetChargeType',
            'transform_func': u
        }
    },
    'operation_locks': {
        'lock_reason': {
            'xpath': 'LockReason',
            'transform_func': u
        }
    },
    'volume': {
        'region_id': {
            'xpath': 'RegionId',
            'transform_func': u
        },
        'zone_id': {
            'xpath': 'ZoneId',
            'transform_func': u
        },
        'description': {
            'xpath': 'Description',
            'transform_func': u
        },
        'type': {
            'xpath': 'Type',
            'transform_func': u
        },
        'category': {
            'xpath': 'Category',
            'transform_func': u
        },
        'image_id': {
            'xpath': 'ImageId',
            'transform_func': u
        },
        'source_snapshot_id': {
            'xpath': 'SourceSnapshotId',
            'transform_func': u
        },
        'product_code': {
            'xpath': 'ProductCode',
            'transform_func': u
        },
        'portable': {
            'xpath': 'Portable',
            'transform_func': _parse_bool
        },
        'instance_id': {
            'xpath': 'InstanceId',
            'transform_func': u
        },
        'device': {
            'xpath': 'Device',
            'transform_func': u
        },
        'delete_with_instance': {
            'xpath': 'DeleteWithInstance',
            'transform_func': _parse_bool
        },
        'enable_auto_snapshot': {
            'xpath': 'EnableAutoSnapshot',
            'transform_func': _parse_bool
        },
        'creation_time': {
            'xpath': 'CreationTime',
            'transform_func': u
        },
        'attached_time': {
            'xpath': 'AttachedTime',
            'transform_func': u
        },
        'detached_time': {
            'xpath': 'DetachedTime',
            'transform_func': u
        },
        'disk_charge_type': {
            'xpath': 'DiskChargeType',
            'transform_func': u
        }
    },
    'snapshot': {
        'snapshot_name': {
            'xpath': 'SnapshotName',
            'transform_func': u
        },
        'description': {
            'xpath': 'Description',
            'transform_func': u
        },
        'progress': {
            'xpath': 'Progress',
            'transform_func': u
        },
        'source_disk_id': {
            'xpath': 'SourceDiskId',
            'transform_func': u
        },
        'source_disk_size': {
            'xpath': 'SourceDiskSize',
            'transform_func': int
        },
        'source_disk_type': {
            'xpath': 'SourceDiskType',
            'transform_func': u
        },
        'product_code': {
            'xpath': 'ProductCode',
            'transform_func': u
        },
        'usage': {
            'xpath': 'Usage',
            'transform_func': u
        }
    },
    'image': {
        'image_version': {
            'xpath': 'ImageVersion',
            'transform_func': u
        },
        'os_type': {
            'xpath': 'OSType',
            'transform_func': u
        },
        'platform': {
            'xpath': 'Platform',
            'transform_func': u
        },
        'architecture': {
            'xpath': 'Architecture',
            'transform_func': u
        },
        'description': {
            'xpath': 'Description',
            'transform_func': u
        },
        'size': {
            'xpath': 'Size',
            'transform_func': int
        },
        'image_owner_alias': {
            'xpath': 'ImageOwnerAlias',
            'transform_func': u
        },
        'os_name': {
            'xpath': 'OSName',
            'transform_func': u
        },
        'product_code': {
            'xpath': 'ProductCode',
            'transform_func': u
        },
        'is_subscribed': {
            'xpath': 'IsSubscribed',
            'transform_func': _parse_bool
        },
        'progress': {
            'xpath': 'Progress',
            'transform_func': u
        },
        'creation_time': {
            'xpath': 'CreationTime',
            'transform_func': u
        },
        'usage': {
            'xpath': 'Usage',
            'transform_func': u
        },
        'is_copied': {
            'xpath': 'IsCopied',
            'transform_func': _parse_bool
        }
    },
    'disk_device_mapping': {
        'snapshot_id': {
            'xpath': 'SnapshotId',
            'transform_func': u
        },
        'size': {
            'xpath': 'Size',
            'transform_func': int
        },
        'device': {
            'xpath': 'Device',
            'transform_func': u
        },
        'format': {
            'xpath': 'Format',
            'transform_func': u
        },
        'import_oss_bucket': {
            'xpath': 'ImportOSSBucket',
            'transform_func': u
        },
        'import_oss_object': {
            'xpath': 'ImportOSSObject',
            'transform_func': u
        }
    }
}


class CVMConnection(SignedTencentConnection):
    """
    Represents a single connection to the Tencent CVM Endpoint.
    """

    api_version = CVM_API_VERSION
    host = CVM_API_ENDPOINT
    responseCls = TencentHTTPResponse
    service_name = 'cvm'


class CVMSecurityGroup(object):
    """
    Security group used to control nodes internet and intranet accessibility.
    """

    def __init__(self,
                 id,
                 name,
                 description=None,
                 driver=None,
                 vpc_id=None,
                 creation_time=None):
        self.id = id
        self.name = name
        self.description = description
        self.driver = driver
        self.vpc_id = vpc_id
        self.creation_time = creation_time

    def __repr__(self):
        return ('<CVMSecurityGroup: id=%s, name=%s, driver=%s ...>' %
                (self.id, self.name, self.driver.name))


class CVMSecurityGroupAttribute(object):
    """
    Security group attribute.
    """

    def __init__(self,
                 ip_protocol=None,
                 port_range=None,
                 source_group_id=None,
                 policy=None,
                 nic_type=None):
        self.ip_protocol = ip_protocol
        self.port_range = port_range
        self.source_group_id = source_group_id
        self.policy = policy
        self.nic_type = nic_type

    def __repr__(self):
        return ('<CVMSecurityGroupAttribute: ip_protocol=%s ...>' %
                (self.ip_protocol))


class CVMZone(object):
    """
    CVMZone used to represent an availability zone in a region.
    """

    def __init__(self,
                 id,
                 name,
                 driver=None,
                 available_resource_types=None,
                 available_instance_types=None,
                 available_disk_categories=None):
        self.id = id
        self.name = name
        self.driver = driver
        self.available_resource_types = available_resource_types
        self.available_instance_types = available_instance_types
        self.available_disk_categories = available_disk_categories

    def __repr__(self):
        return ('<CVMZone: id=%s, name=%s, driver=%s>' %
                (self.id, self.name, self.driver))


class InternetChargeType(object):
    """
    Internet connection billing types for Tencent Nodes.
    """
    BY_BANDWIDTH = 'PayByBandwidth'
    BY_TRAFFIC = 'PayByTraffic'


class DiskCategory(object):
    """
    Enum defined disk types supported by Tencent system and data disks.
    """
    CLOUD = 'cloud'
    CLOUD_EFFICIENCY = 'cloud_efficiency'
    CLOUD_SSD = 'cloud_ssd'
    EPHEMERAL_SSD = 'ephemeral_ssd'


class Pagination(object):
    """
    Pagination used to describe the multiple pages results.
    """

    def __init__(self, total, size, current):
        """
        Create a pagination.

        :param total: the total count of the results
        :param size: the page size of each page
        :param current: the current page number, 1-based
        """
        self.total = total
        self.size = size
        self.current = current

    def next(self):
        """
        Switch to the next page.
        :return: the new pagination or None when no more page
        :rtype: ``Pagination``
        """
        if self.total is None or (self.size * self.current >= self.total):
            return None
        self.current += 1
        return self

    def to_dict(self):
        return {'PageNumber': self.current, 'PageSize': self.size}

    def __repr__(self):
        return ('<Pagination total=%d, size=%d, current page=%d>' %
                (self.total, self.size, self.current))


class CVMDriver(NodeDriver):
    """
    Tencent CVM node driver.

    Used for Tencent CVM service.

    TODO:
    Get guest OS root password
    Adjust internet bandwidth settings
    Manage security groups and rules
    """

    name = 'Tencent CVM'
    website = 'https://account.api.qcloud.com/v2/index.php'
    connectionCls = CVMConnection
    features = {'create_node': ['password', 'ssh_key']}
    namespace = None
    path = '/'

    internet_charge_types = InternetChargeType
    disk_categories = DiskCategory

    NODE_STATE_MAPPING = {
        'Starting': 'PENDING',
        'Running': 'RUNNING',
        'Stopping': 'PENDING',
        'Stopped': 'STOPPED'
    }

    VOLUME_STATE_MAPPING = {
        'In_use': StorageVolumeState.INUSE,
        'Available': StorageVolumeState.AVAILABLE,
        'Attaching': StorageVolumeState.ATTACHING,
        'Detaching': StorageVolumeState.INUSE,
        'Creating': StorageVolumeState.CREATING,
        'ReIniting': StorageVolumeState.CREATING
    }

    SNAPSHOT_STATE_MAPPING = {
        'progressing': VolumeSnapshotState.CREATING,
        'accomplished': VolumeSnapshotState.AVAILABLE,
        'failed': VolumeSnapshotState.ERROR
    }

    def list_nodes(self, ex_node_ids=None, ex_filters=None):
        """
        List all nodes.

        @inherits: :class:`NodeDriver.create_node`

        :keyword  ex_node_ids: a list of node's ids used to filter nodes.
                               Only the nodes which's id in this list
                               will be returned.
        :type   ex_node_ids: ``list`` of ``str``
        :keyword  ex_filters: node attribute and value pairs to filter nodes.
                              Only the nodes which matchs all the pairs will
                              be returned.
                              If the filter attribute need a json array value,
                              use ``list`` object, the driver will convert it.
        :type   ex_filters: ``dict``
        """
        #TODO: not implement testcase of this function

        req = models.DescribeInstancesRequest()
        params = {}
        if ex_node_ids:
            if isinstance(ex_node_ids, list):
                params['InstanceIds'] = ex_node_ids
            else:
                raise AttributeError('ex_node_ids should be a list of '
                                     'node ids.')

        if ex_filters:
            if isinstance(ex_filters, list):
                params['Filters'] = ex_filters
            else:
                raise AttributeError('ex_filters should be a dict of '
                                     'node attributes.')
        # zones
        req.from_json_string(json.dumps(params))
        client = self._cvm_client(self.region)
        resp = client.DescribeInstances(req)
        node_elements = json.loads(resp.to_json_string()).get(
            'InstanceSet', [])
        nodes = [self._to_node(el) for el in node_elements]

        # status
        req = models.DescribeInstancesStatusRequest()
        params = {}
        req.from_json_string(json.dumps(params))
        resp = client.DescribeInstancesStatus(req)
        node_elements = json.loads(resp.to_json_string()).get(
            'InstanceStatusSet', [])
        node_status = self._to_status(node_elements)

        for node in nodes:
            node.state = node_status[node.id]

        return nodes

    def list_sizes(self, location=None):

        if location and isinstance(location, NodeLocation):
            region = location.id
        else:
            region = self.region

        req = models.DescribeInstanceTypeConfigsRequest()
        params = {}
        req.from_json_string(json.dumps(params))

        client = self._cvm_client(region)
        resp = client.DescribeInstanceTypeConfigs(req)
        res = json.loads(resp.to_json_string()).get('InstanceTypeConfigSet',
                                                    [])
        sizes = [self._to_size(each) for each in res]
        return sizes

    def list_locations(self):
        req = models.DescribeZonesRequest()
        params = {}
        req.from_json_string(json.dumps(params))

        client = self._cvm_client(self.region)
        resp = client.DescribeZones(req)
        res = json.loads(resp.to_json_string()).get('ZoneSet', [])
        locations = [self._to_location(each) for each in res]
        return locations

    def list_prices(self, image_id):
        req = models.InquiryPriceRunInstancesRequest()
        params = {
            'Placement': {
                'Zone': self.region + '-1'
            },
            'ImageId': image_id
        }
        req.from_json_string(json.dumps(params))

        client = self._cvm_client(self.region)
        resp = client.InquiryPriceRunInstances(req)
        prices = json.loads(resp.to_json_string()).get('Price', {})
        return prices

    def create_node(self,
                    name,
                    size,
                    image,
                    auth=None,
                    ex_security_group_id=None,
                    ex_internet_charge_type=None,
                    ex_internet_max_bandwidth_out=None,
                    ex_hostname=None,
                    ex_system_disk=None,
                    ex_data_disks=None,
                    ex_private_ip_address=None,
                    ex_client_token=None,
                    **kwargs):
        """
        @inherits: :class:`NodeDriver.create_node`

        :param name: The name for this new node (required)
        :type name: ``str``

        :param image: The image to use when creating this node (required)
        :type image: `NodeImage`

        :param size: The size of the node to create (required)
        :type size: `NodeSize`

        :keyword auth: Initial authentication information for the node
                       (optional)
        :type auth: :class:`NodeAuthSSHKey` or :class:`NodeAuthPassword`

        :keyword ex_security_group_id: The id of the security group the
                                       new created node is attached to.
                                       (required)
        :type ex_security_group_id: ``str``

        :keyword ex_internet_charge_type: The internet charge type (optional)
        :type ex_internet_charge_type: a ``str`` of 'PayByTraffic'
                                       or 'PayByBandwidth'

        :keyword ex_internet_max_bandwidth_out: The max output bandwidth,
                                                in Mbps (optional)
                                                Required for 'PayByTraffic'
                                                internet charge type
        :type ex_internet_max_bandwidth_out: a ``int`` in range [0, 100]
                                             a ``int`` in range [1, 100] for
                                             'PayByTraffic' internet charge
                                             type

        :keyword ex_hostname: The hostname for the node (optional)
        :type ex_hostname: ``str``

        :keyword ex_system_disk: The system disk for the node (optional)
        :type ex_system_disk: ``dict``

        :keyword ex_data_disks: The data disks for the node (optional)
        :type ex_data_disks: a `list` of `dict`

        :keyword ex_private_ip_address: The IP address in private network
                                        (optional)
        :type ex_private_ip_address: ``str``

        :keyword ex_client_token: A token generated by client to keep
                                  requests idempotency (optional)
        :type keyword ex_client_token: ``str``
        """

        params = {
            'ImageId': image.id,
            'InstanceType': size.id,
            'InstanceName': name,
        }

        if not ex_security_group_id:
            raise AttributeError('ex_security_group_id is mandatory')
        params['SecurityGroupIds'] = [ex_security_group_id]
        internetAccessible = {
            'InternetChargeType': ex_internet_charge_type,
            'InternetMaxBandwidthOut': ex_internet_max_bandwidth_out
        }
        params['InternetAccessible'] = internetAccessible

        if ex_hostname:
            params['HostName'] = ex_hostname

        if auth:
            loginSettings = {}
            auth = self._get_and_check_auth(auth)
            loginSettings['Password'] = auth.password
        params['LoginSettings'] = loginSettings

        if ex_system_disk:
            system_disk = self._get_system_disk(ex_system_disk)
            if system_disk:
                params['SystemDisk'] = system_disk

        if ex_data_disks:
            data_disks = self._get_data_disks(ex_data_disks)
            if data_disks:
                params['DataDisk'] = data_disks

        if ex_private_ip_address:
            if not ex_vswitch_id:
                raise AttributeError('must provide ex_private_ip_address  '
                                     'and ex_vswitch_id at the same time')
            else:
                virtualPrivateCloud = {
                    'PrivateIpAddresses': 'ex_private_ip_address'
                }
                params['VirtualPrivateCloud'] = virtualPrivateCloud

        if ex_client_token:
            params['ClientToken'] = ex_client_token

        req = models.RunInstancesRequest()
        req.from_json_string(json.dumps(params))
        client = self._cvm_client(self.region)
        resp = client.RunInstances(req)
        node_id = json.loads(resp.to_json_string()).get('InstanceIdSet', [])
        nodes = self.list_nodes(ex_node_ids=node_id)
        if len(nodes) != 1:
            raise LibcloudError('could not find the new created node '
                                'with id %s. ' % node_id,
                                driver=self)
        node = nodes[0]
        self._wait_until_state([node], 'STOPPED')
        self.ex_start_node(node)
        self._wait_until_state(nodes, 'RUNNING')

        # if 'ex_allocate_public_ip_address' in kwargs:
        #     self.ex_allocate_public_ip(node)
        return node

    def reboot_node(self, node, ex_force_stop=False):
        """
        Reboot the given node

        @inherits :class:`NodeDriver.reboot_node`

        :keyword ex_force_stop: if ``True``, stop node force (maybe lose data)
                                otherwise, stop node normally,
                                default to ``False``
        :type ex_force_stop: ``bool``
        """
        params = {
            'InstanceIds': [node.id],
            'ForceStop': u(ex_force_stop).lower()
        }
        req = models.RebootInstancesRequest()
        req.from_json_string(json.dumps(params))
        client = self._cvm_client(self.region)
        resp = client.RebootInstances(req)
        res = json.loads(resp.to_json_string())

        return self._wait_until_state([node], 'RUNNING')

    def destroy_node(self, node):
        nodes = self.list_nodes(ex_node_ids=[node.id])
        if len(nodes) != 1 and node.id != nodes[0].id:
            raise LibcloudError('could not find the node with id %s.' %
                                node.id)
        current = nodes[0]
        if current.state == 'RUNNING':
            # stop node first
            self.ex_stop_node(node)
            self._wait_until_state(nodes, 'STOPPED')

        params = {'InstanceIds': [node.id]}
        req = models.TerminateInstancesRequest()
        req.from_json_string(json.dumps(params))
        client = self._cvm_client(self.region)
        resp = client.TerminateInstances(req)
        res = json.loads(resp.to_json_string())
        return res

    def ex_start_node(self, node):
        """
        Start node to running state.

        :param node: the ``Node`` object to start
        :type node: ``Node``

        :return: starting operation result.
        :rtype: ``bool``
        """
        req = models.StartInstancesRequest()
        params = {'InstanceIds': [node.id]}
        req.from_json_string(json.dumps(params))
        client = self._cvm_client(self.region)
        resp = client.StartInstances(req)
        res = json.loads(resp.to_json_string())

        return self._wait_until_state([node], 'RUNNING')

    def ex_stop_node(self, node, ex_force_stop=False):
        """
        Stop a running node.

        :param node: The node to stop
        :type node: :class:`Node`

        :keyword ex_force_stop: if ``True``, stop node force (maybe lose data)
                                otherwise, stop node normally,
                                default to ``False``
        :type ex_force_stop: ``bool``

        :return: stopping operation result.
        :rtype: ``bool``
        """

        req = models.StopInstancesRequest()
        params = {'InstanceIds': [node.id]}
        req.from_json_string(json.dumps(params))
        client = self._cvm_client(self.region)
        resp = client.StopInstances(req)
        res = json.loads(resp.to_json_string())

        return self._wait_until_state([node], 'STOPPED')

    def ex_resize_node(self, node, size):
        """
        Resize a node

        :param node: The node to resize
        :param size: The new size of the node
        """

        req = models.ResizeInstanceDisksRequest()
        params = {'InstanceId': node.id, 'DataDisks': [{'DiskSize': size}]}
        req.from_json_string(json.dumps(params))
        client = self._cvm_client(self.region)
        resp = client.ResizeInstanceDisks(req)
        res = json.loads(resp.to_json_string())

        return res

    def ex_create_security_group(self, description=None, name=None):
        """
        Create a new security group.

        :keyword description: security group description
        :type description: ``unicode``

        :keyword client_token: a token generated by client to identify
                                  each request.
        :type client_token: ``str``
        """
        params = {}
        if description:
            params['GroupDescription'] = description
        else:
            AttributeError('GroupDescription is required')
        if name:
            params['GroupName'] = name
        else:
            AttributeError('GroupName is required')

        req = vpc_models.CreateSecurityGroupRequest()
        req.from_json_string(json.dumps(params))
        client = self._vpc_client(self.region)
        resp = client.CreateSecurityGroup(req)
        res = json.loads(resp.to_json_string()).get('SecurityGroup', {})
        return res

    def ex_delete_security_group_by_id(self, group_id=None):
        """
        Delete a new security group.

        :keyword group_id: security group id
        :type group_id: ``str``
        """
        params = {}
        if group_id:
            params['SecurityGroupId'] = group_id
        else:
            AttributeError('SecurityGroupId is required')

        req = vpc_models.DeleteSecurityGroupRequest()
        req.from_json_string(json.dumps(params))
        client = self._vpc_client(self.region)
        resp = client.DeleteSecurityGroup(req)
        RequestID = json.loads(resp.to_json_string()).get('RequestID', {})

        return RequestID

    def ex_modify_security_group_by_id(self,
                                       group_id=None,
                                       name=None,
                                       description=None):
        """
        Modify a new security group.
        :keyword group_id: id of the security group
        :type group_id: ``str``
        :keyword name: new name of the security group
        :type name: ``unicode``
        :keyword description: new description of the security group
        :type description: ``unicode``
        """

        params = {
            'Action': 'ModifySecurityGroupAttribute',
            'RegionId': self.region
        }
        if not group_id:
            raise AttributeError('group_id is required')
        params["SecurityGroupId"] = group_id

        if name:
            params["SecurityGroupName"] = name
        if description:
            params["Description"] = description

        resp = self.connection.request(self.path, params)
        return resp.success()

    def ex_modify_security_group_rule(self,
                                      group_id,
                                      description,
                                      ip_protocol,
                                      port_range,
                                      source_port_range=None,
                                      nic_type=None,
                                      policy='accept',
                                      dest_cidr_ip='0.0.0.0/0',
                                      source_cidr_ip='0.0.0.0/0',
                                      priority=None):
        """
        Modify a security group rule.
        :keyword group_id: id of the security group
        :type group_id: ``str``
        :keyword description: new description of the security group
        :type description: ``unicode``
        :keyword ip_protocol: IP protocol (icmp, gre, tcp, udl, all)
        :type ip_protocol: ``unicode``
        :keyword: port_range: Range of the port numbers of a specific protocol
        """

        params = {
            'Action': 'ModifySecurityGroupRule',
            'RegionId': self.region,
            'SecurityGroupId': group_id,
            'Description': description,
            'IpProtocol': ip_protocol,
            'PortRange': port_range,
            'Policy': policy,
            'DestCidrIp': dest_cidr_ip,
            'SourceCidrIp': source_cidr_ip
        }

        if not group_id:
            raise AttributeError('group_id is required')

        if source_port_range:
            params["SourcePortRange"] = source_port_range
        if nic_type:
            params["Nictype"] = nic_type
        if priority:
            params['Priority'] = priority

        resp = self.connection.request(self.path, params)
        return resp.success()

    def ex_authorize_security_group(self,
                                    group_id,
                                    description,
                                    ip_protocol,
                                    port_range,
                                    source_port_range=None,
                                    nic_type=None,
                                    policy='accept',
                                    dest_cidr_ip=None,
                                    source_cidr_ip='0.0.0.0/0',
                                    priority=None):
        """
        Modify a security group rule.
        :keyword group_id: id of the security group
        :type group_id: ``str``
        :keyword description: new description of the security group
        :type description: ``unicode``
        :keyword ip_protocol: IP protocol (icmp, gre, tcp, udl, all)
        :type ip_protocol: ``unicode``
        :keyword: port_range: Range of the port numbers of a specific protocol
        """

        params = {
            'Action': 'AuthorizeSecurityGroup',
            'RegionId': self.region,
            'SecurityGroupId': group_id,
            'Description': description,
            'IpProtocol': ip_protocol,
            'PortRange': port_range,
            'Policy': policy,
            'SourceCidrIp': source_cidr_ip
        }

        if not group_id:
            raise AttributeError('group_id is required')

        if source_port_range:
            params["SourcePortRange"] = source_port_range
        if nic_type:
            params["Nictype"] = nic_type
        if priority:
            params['Priority'] = priority
        if dest_cidr_ip:
            params['DestCidrIp'] = dest_cidr_ip

        resp = self.connection.request(self.path, params)
        return resp.success()

    def ex_list_security_groups(self, ex_filters=None):
        """
        List security groups in the current region.

        :keyword ex_filters: security group attributes to filter results.
        :type ex_filters: ``dict``

        :return: a list of defined security groups
        :rtype: ``list`` of ``CVMSecurityGroup``
        """
        params = {'Action': 'DescribeSecurityGroups', 'RegionId': self.region}

        if ex_filters and isinstance(ex_filters, dict):
            ex_filters.update(params)
            params = ex_filters

        def _parse_response(resp_object):
            sg_elements = findall(resp_object,
                                  'SecurityGroups/SecurityGroup',
                                  namespace=self.namespace)
            sgs = [self._to_security_group(el) for el in sg_elements]
            return sgs

        return self._request_multiple_pages(self.path, params, _parse_response)

    def ex_list_security_group_attributes(self,
                                          group_id=None,
                                          nic_type='internet'):
        """
        List security group attributes in the current region.

        :keyword group_id: security group id.
        :type group_id: ``str``

        :keyword nic_type: internet|intranet.
        :type nic_type: ``str``

        :return: a list of defined security group Attributes
        :rtype: ``list`` of ``CVMSecurityGroupAttribute``
        """
        params = {
            'Action': 'DescribeSecurityGroupAttribute',
            'RegionId': self.region,
            'NicType': nic_type
        }

        if group_id is None:
            raise AttributeError('group_id is required')
        params['SecurityGroupId'] = group_id

        resp_object = self.connection.request(self.path, params).object
        sga_elements = findall(resp_object,
                               'Permissions/Permission',
                               namespace=self.namespace)
        return [self._to_security_group_attribute(el) for el in sga_elements]

    def ex_join_security_group(self, node, group_id=None):
        """
        Join a node into security group.

        :param node: The node to join security group
        :type node: :class:`Node`

        :param group_id: security group id.
        :type group_id: ``str``


        :return: join operation result.
        :rtype: ``bool``
        """

        if group_id is None:
            raise AttributeError('group_id is required')

        if node.state != 'RUNNING' and \
           node.state != 'STOPPED':
            raise LibcloudError('The node state with id % s need\
                                be running or stopped .' % node.id)

        if isinstance(node.id, list):
            InstanceIds = node.id
        elif isinstance(node.id, str):
            InstanceIds = [node.id]
        if isinstance(group_id, list):
            SecurityGroupIds = group_id
        elif isinstance(group_id, str):
            SecurityGroupIds = [group_id]
        params = {
            'InstanceIds': [InstanceIds],
            'SecurityGroupIds': SecurityGroupIds
        }
        req = models.AssociateSecurityGroupsRequest()
        req.from_json_string(json.dumps(params))

        client = self._cvm_client(region)
        resp = client.AssociateSecurityGroups(req)
        RequestId = json.loads(resp.to_json_string()).get('RequestId', '')

        return RequestId

    def ex_leave_security_group(self, node, group_id=None):
        """
        Leave a node from security group.

        :param node: The node to leave security group
        :type node: :class:`Node`

        :param group_id: security group id.
        :type group_id: ``str``


        :return: leave operation result.
        :rtype: ``bool``
        """
        if group_id is None:
            raise AttributeError('group_id is required')

        if node.state != 'RUNNING' and \
           node.state != 'STOPPED':
            raise LibcloudError('The node state with id % s need\
                                be running or stopped .' % node.id)

        if isinstance(node.id, list):
            InstanceIds = node.id
        elif isinstance(node.id, str):
            InstanceIds = [node.id]
        if isinstance(group_id, list):
            SecurityGroupIds = group_id
        elif isinstance(group_id, str):
            SecurityGroupIds = [group_id]
        params = {
            'InstanceIds': [InstanceIds],
            'SecurityGroupIds': SecurityGroupIds
        }
        req = models.DisassociateSecurityGroupsRequest()
        req.from_json_string(json.dumps(params))
        client = self._cvm_client(region)
        resp = client.DisassociateSecurityGroups(req)
        RequestId = json.loads(resp.to_json_string()).get('RequestId', '')

        return RequestId

    def ex_list_zones(self, region_id=None):
        """
        List availability zones in the given region or the current region.

        :keyword region_id: the id of the region to query zones from
        :type region_id: ``str``

        :return: list of zones
        :rtype: ``list`` of ``CVMZone``
        """
        region = region_id if region_id else self.region

        # get zone info
        req = models.DescribeZonesRequest()
        params = {}
        req.from_json_string(json.dumps(params))

        client = self._cvm_client(region)
        resp = client.DescribeZones(req)
        zone_elements = json.loads(resp.to_json_string()).get('ZoneSet', [])

        zones = [self._to_zone(el) for el in zone_elements]

        # get instance info
        req = models.DescribeInstanceTypeConfigsRequest()
        req.from_json_string(json.dumps(params))

        client = self._cvm_client(region)
        resp = client.DescribeInstanceTypeConfigs(req)
        instances = json.loads(resp.to_json_string()).get(
            'InstanceTypeConfigSet', [])

        instances_elements = self._to_instance(instances)

        # get disk info
        req = cbs_models.DescribeDiskConfigQuotaRequest()
        params = '{"InquiryType":"INQUIRY_CVM_CONFIG"}'
        req.from_json_string(params)

        client = self._cbs_client(region)
        resp = client.DescribeDiskConfigQuota(req)
        disks = json.loads(resp.to_json_string()).get('DiskConfigSet', [])
        disks_elements = self._to_disk(disks)

        for zone in zones:
            zone.available_instance_types = instances_elements.get(zone.id, [])
            zone.available_disk_categories = list(
                disks_elements.get(zone.id, set([])))
        return zones

    ##
    # Volume and snapshot management methods
    ##

    def list_volumes(self, ex_volume_ids=None, ex_filters=None):
        """
        List all volumes.

        @inherits: :class:`NodeDriver.list_volumes`

        :keyword ex_volume_ids: a list of volume's ids used to filter volumes.
                                Only the volumes which's id in this list
                                will be returned.
        :type ex_volume_ids: ``list`` of ``str``

        :keyword ex_filters: volume attribute and value pairs to filter
                             volumes. Only the volumes which matchs all will
                             be returned.
                             If the filter attribute need a json array value,
                             use ``list`` object, the driver will convert it.
        :type ex_filters: ``dict``
        """
        params = {'Action': 'DescribeDisks', 'RegionId': self.region}

        if ex_volume_ids:
            if isinstance(ex_volume_ids, list):
                params['DiskIds'] = self._list_to_json_array(ex_volume_ids)
            else:
                raise AttributeError('ex_volume_ids should be a list of '
                                     'volume ids.')

        if ex_filters:
            if not isinstance(ex_filters, dict):
                raise AttributeError('ex_filters should be a dict of '
                                     'volume attributes.')
            else:
                for key in ex_filters.keys():
                    params[key] = ex_filters[key]

        def _parse_response(resp_object):
            disk_elements = findall(resp_object,
                                    'Disks/Disk',
                                    namespace=self.namespace)
            volumes = [self._to_volume(each) for each in disk_elements]
            return volumes

        return self._request_multiple_pages(self.path, params, _parse_response)

    def list_volume_snapshots(self,
                              volume,
                              ex_snapshot_ids=[],
                              ex_filters=None):
        """
        List snapshots for a storage volume.

        @inherites :class:`NodeDriver.list_volume_snapshots`

        :keyword ex_snapshot_ids: a list of snapshot ids to filter the
                                  snapshots returned.
        :type ex_snapshot_ids: ``list`` of ``str``

        :keyword ex_filters: snapshot attribute and value pairs to filter
                             snapshots. Only the snapshot which matchs all
                             the pairs will be returned.
                             If the filter attribute need a json array value,
                             use ``list`` object, the driver will convert it.
        :type ex_filters: ``dict``
        """
        params = {'Action': 'DescribeSnapshots', 'RegionId': self.region}

        if volume:
            params['DiskId'] = volume.id
        if ex_snapshot_ids and isinstance(ex_snapshot_ids, list):
            params['SnapshotIds'] = self._list_to_json_array(ex_snapshot_ids)
        if ex_filters and isinstance(ex_filters, dict):
            for key in ex_filters.keys():
                params[key] = ex_filters[key]

        def _parse_response(resp_body):
            snapshot_elements = findall(resp_body,
                                        'Snapshots/Snapshot',
                                        namespace=self.namespace)
            snapshots = [self._to_snapshot(each) for each in snapshot_elements]
            return snapshots

        return self._request_multiple_pages(self.path, params, _parse_response)

    def create_volume(self,
                      size,
                      name,
                      location=None,
                      snapshot=None,
                      ex_zone_id=None,
                      ex_description=None,
                      ex_disk_category=None,
                      ex_client_token=None):
        """
        Create a new volume.

        @inherites :class:`NodeDriver.create_volume`

        :keyword ex_zone_id: the availability zone id (required)
        :type ex_zone_id: ``str``

        :keyword ex_description: volume description
        :type ex_description: ``unicode``

        :keyword ex_disk_category: disk category for data disk
        :type ex_disk_category: ``str``

        :keyword ex_client_token: a token generated by client to identify
                                  each request.
        :type ex_client_token: ``str``
        """
        params = {
            'Action': 'CreateDisk',
            'RegionId': self.region,
            'DiskName': name,
            'Size': size
        }
        if ex_zone_id is None:
            raise AttributeError('ex_zone_id is required')
        params['ZoneId'] = ex_zone_id

        if snapshot is not None and isinstance(snapshot, VolumeSnapshot):
            params['SnapshotId'] = snapshot.id
        if ex_description:
            params['Description'] = ex_description
        if ex_disk_category:
            params['DiskCategory'] = ex_disk_category
        if ex_client_token:
            params['ClientToken'] = ex_client_token
        resp = self.connection.request(self.path, params).object
        volume_id = findtext(resp, 'DiskId', namespace=self.namespace)
        volumes = self.list_volumes(ex_volume_ids=[volume_id])
        if len(volumes) != 1:
            raise LibcloudError('could not find the new create volume '
                                'with id %s.' % volume_id,
                                driver=self)
        return volumes[0]

    def create_volume_snapshot(self,
                               volume,
                               name=None,
                               ex_description=None,
                               ex_client_token=None):
        """
        Creates a snapshot of the storage volume.

        @inherits :class:`NodeDriver.create_volume_snapshot`

        :keyword ex_description: description of the snapshot.
        :type ex_description: ``unicode``

        :keyword ex_client_token: a token generated by client to identify
                                  each request.
        :type ex_client_token: ``str``
        """
        params = {'Action': 'CreateSnapshot', 'DiskId': volume.id}
        if name:
            params['SnapshotName'] = name
        if ex_description:
            params['Description'] = ex_description
        if ex_client_token:
            params['ClientToken'] = ex_client_token

        snapshot_elements = self.connection.request(self.path, params).object
        snapshot_id = findtext(snapshot_elements,
                               'SnapshotId',
                               namespace=self.namespace)
        snapshots = self.list_volume_snapshots(volume=None,
                                               ex_snapshot_ids=[snapshot_id])
        if len(snapshots) != 1:
            raise LibcloudError('could not find new created snapshot with '
                                'id %s.' % snapshot_id,
                                driver=self)
        return snapshots[0]

    def attach_volume(self,
                      node,
                      volume,
                      device=None,
                      ex_delete_with_instance=None):
        """
        Attaches volume to node.

        @inherits :class:`NodeDriver.attach_volume`

        :keyword device: device path allocated for this attached volume
        :type device: ``str`` between /dev/xvdb to xvdz,
                      if empty, allocated by the system
        :keyword ex_delete_with_instance: if to delete this volume when the
                                          instance is deleted.
        :type ex_delete_with_instance: ``bool``
        """
        params = {
            'Action': 'AttachDisk',
            'InstanceIds': node.id,
            'DiskId': volume.id
        }

        if device:
            params['Device'] = device
        if ex_delete_with_instance:
            params['DeleteWithInstance'] = \
                str(bool(ex_delete_with_instance)).lower()
        resp = self.connection.request(self.path, params)
        return resp.success()

    def detach_volume(self, volume, ex_instance_id=None):
        """
        Detaches a volume from a node.

        @inherits :class:`NodeDriver.detach_volume`

        :keyword ex_instance_id: the id of the instance from which the volume
                                 is detached.
        :type ex_instance_id: ``str``
        """
        params = {'Action': 'DetachDisk', 'DiskId': volume.id}

        if ex_instance_id:
            params['InstanceId'] = ex_instance_id
        else:
            volumes = self.list_volumes(ex_volume_ids=[volume.id])
            if len(volumes) != 1:
                raise AttributeError('could not find the instance id '
                                     'the volume %s attached to, '
                                     'ex_instance_id is required.' % volume.id)
            params['InstanceId'] = volumes[0].extra['instance_id']

        resp = self.connection.request(self.path, params)
        return resp.success()

    def destroy_volume(self, volume):
        params = {'Action': 'DeleteDisk', 'DiskId': volume.id}
        volumes = self.list_volumes(ex_volume_ids=[volume.id])
        if len(volumes) != 1:
            raise LibcloudError('could not find the volume with id %s.' %
                                volume.id,
                                driver=self)
        if volumes[0].state != StorageVolumeState.AVAILABLE:
            raise LibcloudError(
                'only volume in AVAILABLE state could be '
                'destroyed.',
                driver=self)
        resp = self.connection.request(self.path, params)
        return resp.success()

    def destroy_volume_snapshot(self, snapshot):
        params = {'Action': 'DeleteSnapshot'}

        if snapshot and isinstance(snapshot, VolumeSnapshot):
            params['SnapshotId'] = snapshot.id
        else:
            raise AttributeError('snapshot is required and must be a '
                                 'VolumeSnapshot')
        resp = self.connection.request(self.path, params)
        return resp.success()

    ##
    # Image management methods
    ##

    def list_images(self, location=None, ex_image_ids=None, ex_filters=None):
        """
        List images on a provider.

        @inherits :class:`NodeDriver.list_images`

        :keyword ex_image_ids: a list of image ids to filter the images to
                               be returned.
        :type ex_image_ids: ``list`` of ``str``

        :keyword ex_filters: image attribute and value pairs to filter
                             images. Only the image which matchs all
                             the pairs will be returned.
                             If the filter attribute need a json array value,
                             use ``list`` object, the driver will convert it.
        :type ex_filters: ``dict``
        """
        if location and isinstance(location, NodeLocation):
            region = location.id
        else:
            region = self.region
        req = models.DescribeImagesRequest()
        params = {}
        req.from_json_string(json.dumps(params))

        client = self._cvm_client(region)
        resp = client.DescribeImages(req)
        res = json.loads(resp.to_json_string()).get('ImageSet', [])

        def _parse_response(res):
            images = [self._to_image(each) for each in res]
            return images

        return _parse_response(res)

    def create_public_ip(self, instance_id):
        """
        Create public ip.

        :keyword instance_id: instance id for allocating public ip.
        :type    instance_id: ``str``

        :return public ip
        :rtype ``str``
        """
        params = {
            'Action': 'AllocatePublicIpAddress',
            'InstanceId': instance_id
        }

        resp = self.connection.request(self.path, params=params)
        return findtext(resp.object, 'IpAddress', namespace=self.namespace)

    def _to_node(self, instance):
        """
        Convert an InstanceAttributesType object to ``Node`` object

        :param instance: a xml element represents an instance
        :return: a ``Node`` object
        :rtype: ``Node``
        """
        _id = instance['InstanceId']
        name = instance['InstanceName']
        state = ''
        public_ips = instance['PublicIpAddresses']
        private_ips = instance['PrivateIpAddresses']

        # Extra properties
        extra = {}

        node = Node(id=_id,
                    name=name,
                    state=state,
                    public_ips=public_ips,
                    private_ips=private_ips,
                    driver=self.connection.driver,
                    extra=extra)
        return node

    def _get_extra_dict(self, element, mapping):
        """
        Extract attributes from the element based on rules provided in the
        mapping dictionary.

        :param      element: Element to parse the values from.
        :type       element: xml.etree.ElementTree.Element.

        :param      mapping: Dictionary with the extra layout
        :type       node: :class:`Node`

        :rtype: ``dict``
        """
        extra = {}
        for attribute, values in mapping.items():
            transform_func = values['transform_func']
            value = findattr(element=element,
                             xpath=values['xpath'],
                             namespace=self.namespace)
            if value:
                try:
                    extra[attribute] = transform_func(value)
                except Exception:
                    extra[attribute] = None
            else:
                extra[attribute] = value

        return extra

    def _get_system_disk(self, ex_system_disk):
        params = {}
        if not isinstance(ex_system_disk, dict):
            raise AttributeError('ex_system_disk is not a dict')
        if ex_system_disk.get('DiskType'):
            params['DiskType'] = ex_system_disk.get('DiskType')
        if ex_system_disk.get('DiskId'):
            params['DiskId'] = ex_system_disk.get('DiskId')
        if ex_system_disk.get('DiskSize'):
            params['DiskSize'] = ex_system_disk.get('DiskSize')
        return params

    def _make_data_disks(data_disks):
        params = {}
        if data_disks.get('DiskSize') and isinstance(
                data_disks.get('DiskSize'), int):
            params['DiskSize'] = data_disks.get('DiskSize')
        if data_disks.get('DiskType') and data_disks.get(
                'DiskType').upper() in TYPE_LIST:
            params['DiskType'] = data_disks.get('DiskType').upper()
        if data_disks.get('DiskId') and instance(data_disks.get('DiskId'),
                                                 str):
            params['DiskId'] = data_disks.get('DiskId')
        if data_disks.get('DeleteWithInstance') and instance(
                data_disks.get('DeleteWithInstance'), bool):
            params['DeleteWithInstance'] = data_disks.get('DeleteWithInstance')
        if data_disks.get('SnapshotId') and instance(
                data_disks.get('SnapshotId'), str):
            params['SnapshotId'] = data_disks.get('SnapshotId')
        return params

    def _get_data_disks(self, ex_data_disks):
        TYPE_LIST = [
            'LOCAL_BASIC', 'LOCAL_SSD', 'CLOUD_BASIC', 'CLOUD_PREMIUM',
            'CLOUD_SSD：SSD'
        ]

        if isinstance(ex_data_disks, dict):
            return [_make_data_disks(ex_data_disks)]
        elif isinstance(ex_data_disks, list):
            return [_make_data_disks(edd) for edd in ex_data_disks]
        else:
            raise AttributeError('ex_data_disks should be a list of dict')

    def _get_vpc_attributes(self, instance):
        vpcs = findall(instance,
                       xpath='VpcAttributes',
                       namespace=self.namespace)
        if len(vpcs) <= 0:
            return None
        return self._get_extra_dict(
            vpcs[0], RESOURCE_EXTRA_ATTRIBUTES_MAP['vpc_attributes'])

    def _get_eip_address(self, instance):
        eips = findall(instance, xpath='EipAddress', namespace=self.namespace)
        if len(eips) <= 0:
            return None
        return self._get_extra_dict(
            eips[0], RESOURCE_EXTRA_ATTRIBUTES_MAP['eip_address_associate'])

    def _get_operation_locks(self, instance):
        locks = findall(instance,
                        xpath='OperationLocks',
                        namespace=self.namespace)
        if len(locks) <= 0:
            return None
        return self._get_extra_dict(
            locks[0], RESOURCE_EXTRA_ATTRIBUTES_MAP['operation_locks'])

    def _wait_until_state(self, nodes, state, wait_period=3, timeout=600):
        """
        Block until the provided nodes are in the desired state.
        :param nodes: List of nodes to wait for
        :type nodes: ``list`` of :class:`.Node`
        :param state: desired state
        :type state: ``NodeState``
        :param wait_period: How many seconds to wait between each loop
                            iteration. (default is 3)
        :type wait_period: ``int``
        :param timeout: How many seconds to wait before giving up.
                        (default is 600)
        :type timeout: ``int``
        :return: if the nodes are in the desired state.
        :rtype: ``bool``
        """
        start = time.time()
        end = start + timeout
        node_ids = [node.id for node in nodes]

        while (time.time() < end):
            matched_nodes = self.list_nodes(ex_node_ids=node_ids)
            if len(matched_nodes) > len(node_ids):
                found_ids = [node.id for node in matched_nodes]
                msg = ('found multiple nodes with same ids, '
                       'desired ids: %(ids)s, found ids: %(found_ids)s' % {
                           'ids': node_ids,
                           'found_ids': found_ids
                       })
                raise LibcloudError(value=msg, driver=self)
            desired_nodes = [
                node for node in matched_nodes if node.state == state
            ]

            if len(desired_nodes) == len(node_ids):
                return True
            else:
                time.sleep(wait_period)
                continue

        raise LibcloudError(value='Timed out after %s seconds' % (timeout),
                            driver=self)

    def _to_volume(self, element):
        _id = findtext(element, 'DiskId', namespace=self.namespace)
        name = findtext(element, 'DiskName', namespace=self.namespace)
        size = int(findtext(element, 'Size', namespace=self.namespace))
        status_str = findtext(element, 'Status', namespace=self.namespace)
        status = self.VOLUME_STATE_MAPPING.get(status_str,
                                               StorageVolumeState.UNKNOWN)

        extra = self._get_extra_dict(element,
                                     RESOURCE_EXTRA_ATTRIBUTES_MAP['volume'])
        extra['operation_locks'] = self._get_operation_locks(element)
        return StorageVolume(_id, name, size, self, state=status, extra=extra)

    def _list_to_json_array(self, value):
        try:
            return json.dumps(value)
        except Exception:
            raise AttributeError('could not convert list to json array')

    def _to_snapshot(self, element):
        _id = findtext(element, 'SnapshotId', namespace=self.namespace)
        created = findtext(element, 'CreationTime', namespace=self.namespace)
        status_str = findtext(element, 'Status', namespace=self.namespace)
        state = self.SNAPSHOT_STATE_MAPPING.get(status_str,
                                                VolumeSnapshotState.UNKNOWN)
        extra = self._get_extra_dict(element,
                                     RESOURCE_EXTRA_ATTRIBUTES_MAP['snapshot'])
        return VolumeSnapshot(id=_id,
                              driver=self,
                              extra=extra,
                              created=created,
                              state=state)

    def _to_size(self, resp):
        _id = resp['InstanceType']
        ram = float(0)
        extra = {}
        extra['cpu_core_count'] = int(resp['CPU'])
        extra['instance_type_family'] = resp['InstanceFamily']
        return NodeSize(id=_id,
                        name=_id,
                        ram=ram,
                        disk=None,
                        bandwidth=None,
                        price=None,
                        driver=self,
                        extra=extra)

    def _to_status(self, status):
        res = {}
        for statu in status:
            res[statu['InstanceId']] = statu['InstanceState']
        return res

    def _to_location(self, resp):
        _id = resp['Zone']
        localname = resp['ZoneName']
        return NodeLocation(id=_id, name=localname, country=None, driver=self)

    def _to_image(self, resp):
        _id = resp['ImageId']
        name = resp['ImageName']
        extra = {'arch': resp['Architecture'], 'family': resp['Platform']}
        return NodeImage(id=_id, name=name, driver=self, extra=extra)

    def _get_disk_device_mappings(self, element):
        if element is None:
            return None
        mapping_element = element.find('DiskDeviceMapping')
        if mapping_element is not None:
            return self._get_extra_dict(
                mapping_element,
                RESOURCE_EXTRA_ATTRIBUTES_MAP['disk_device_mapping'])
        return None

    def _to_security_group(self, element):
        _id = findtext(element, 'SecurityGroupId', namespace=self.namespace)
        name = findtext(element, 'SecurityGroupName', namespace=self.namespace)
        description = findtext(element,
                               'Description',
                               namespace=self.namespace)
        vpc_id = findtext(element, 'VpcId', namespace=self.namespace)
        creation_time = findtext(element,
                                 'CreationTime',
                                 namespace=self.namespace)
        return CVMSecurityGroup(_id,
                                name,
                                description=description,
                                driver=self,
                                vpc_id=vpc_id,
                                creation_time=creation_time)

    def _to_security_group_attribute(self, element):
        ip_protocol = findtext(element, 'IpProtocol', namespace=self.namespace)
        port_range = findtext(element, 'PortRange', namespace=self.namespace)
        source_group_id = findtext(element,
                                   'SourceGroupId',
                                   namespace=self.namespace)
        policy = findtext(element, 'Policy', namespace=self.namespace)
        nic_type = findtext(element, 'NicType', namespace=self.namespace)
        return CVMSecurityGroupAttribute(ip_protocol=ip_protocol,
                                         port_range=port_range,
                                         source_group_id=source_group_id,
                                         policy=policy,
                                         nic_type=nic_type)

    def _to_zone(self, zones):
        _id = zones['Zone']
        local_name = zones['ZoneName']

        return CVMZone(id=_id,
                       name=local_name,
                       driver=self,
                       available_resource_types=[],
                       available_instance_types=[],
                       available_disk_categories=[])

    def _to_instance(self, instances):
        available_instance_types = {}
        for i in instances:
            if available_instance_types.get(
                    i['Zone']) or available_instance_types.get(
                        i['Zone']) == []:
                available_instance_types[i['Zone']].append(i['InstanceType'])
            else:
                available_instance_types[i['Zone']] = []
        return available_instance_types

    def _to_disk(self, disks):
        available_disk_categories = {}
        for i in disks:
            if available_disk_categories.get(
                    i['Zone']) or available_disk_categories.get(
                        i['Zone']) == set([]):
                available_disk_categories[i['Zone']].add(i['DiskType'])
            else:
                available_disk_categories[i['Zone']] = set([])
        return available_disk_categories

    def _get_pagination(self, element):
        page_number = int(findtext(element, 'PageNumber'))
        total_count = int(findtext(element, 'TotalCount'))
        page_size = int(findtext(element, 'PageSize'))
        return Pagination(total=total_count,
                          size=page_size,
                          current=page_number)

    def _cvm_client(self, region):
        cred = credential.Credential(self.key, self.secret)
        httpProfile = HttpProfile()
        httpProfile.endpoint = "cvm.tencentcloudapi.com"

        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile
        client = cvm_client.CvmClient(cred, region, clientProfile)
        return client

    def _cbs_client(self, region):
        cred = credential.Credential(self.key, self.secret)
        httpProfile = HttpProfile()
        httpProfile.endpoint = "cbs.tencentcloudapi.com"

        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile
        client = cbs_client.CbsClient(cred, region, clientProfile)
        return client

    def _vpc_client(self, region):
        cred = credential.Credential(self.key, self.secret)
        httpProfile = HttpProfile()
        httpProfile.endpoint = "vpc.tencentcloudapi.com"

        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile
        client = vpc_client.VpcClient(cred, region, clientProfile)
        return client

    def _request_multiple_pages(self, path, params, parse_func):
        """
        Request all resources by multiple pages.
        :param path: the resource path
        :type path: ``str``
        :param params: the query parameters
        :type params: ``dict``
        :param parse_func: the function object to parse the response body
        :param type: ``function``
        :return: list of resource object, if not found any, return []
        :rtype: ``list``
        """
        results = []
        while True:
            one_page = self.connection.request(path, params).object
            resources = parse_func(one_page)
            results += resources
            pagination = self._get_pagination(one_page)
            if pagination.next() is None:
                break
            params.update(pagination.to_dict())
        return results

    # Key pair management methods

    def list_key_pairs(self):
        params = {}
        req = models.DescribeKeyPairsRequest()
        req.from_json_string(json.dumps(params))

        client = self._cvm_client(self.region)
        resp = client.DescribeKeyPairs(req)

        key_elements = json.loads(resp.to_json_string()).get('KeyPairSet', [])

        key_pairs = [self._to_key_pair(keys=elem) for elem in key_elements]
        return key_pairs

    def get_key_pair(self, name):
        params = {}
        Filters = [{'Name': 'key-name', 'Values': [name]}]
        params['Filters'] = Filters
        req = models.DescribeKeyPairsRequest()
        req.from_json_string(json.dumps(params))

        client = self._cvm_client(self.region)
        resp = client.DescribeKeyPairs(req)

        key_elements = json.loads(resp.to_json_string()).get('KeyPairSet', [])

        key_pairs = [self._to_key_pair(keys=elem) for elem in key_elements]
        if key_pairs:
            return key_pairs[0]
        else:
            return []

    def create_key_pair(self, name, project_id=0):
        params = {'KeyName': name, 'ProjectId': project_id}
        req = models.CreateKeyPairRequest()
        req.from_json_string(json.dumps(params))

        client = self._cvm_client(self.region)
        resp = client.CreateKeyPair(req)
        key_elements = json.loads(resp.to_json_string()).get('KeyPair', [])
        key_pair = self._to_key_pair(keys=key_elements)
        return key_pair

    def import_key_pair_from_string(self, name, publickey, project_id):
        params = {
            'KeyName': name,
            'ProjectId': project_id,
            'PublicKey': PublicKey
        }
        req = models.ImportKeyPairRequest()
        req.from_json_string(json.dumps(params))

        client = self._cvm_client(self.region)
        resp = client.ImportKeyPair(req)
        key_ID = json.loads(resp.to_json_string()).get('KeyId', [])
        return KeyPair(name=key_ID,
                       public_key=None,
                       fingerprint=None,
                       driver=self)

    def delete_key_pair(self, key_id):
        if isinstance(key_id, str):
            keyId = [key_id]
        elif isinstance(key_id, list):
            keyId = key_id
        else:
            raise AttributeError('keyId must be list of string or string')

        params = {'KeyIds': keyId}
        req = models.DeleteKeyPairsRequest()
        req.from_json_string(json.dumps(params))

        client = self._cvm_client(self.region)
        resp = client.DeleteKeyPairs(req)

        RequestId = json.loads(resp.to_json_string()).get('RequestId', [])

        return RequestId

    def _get_pubkey_ssh2_fingerprint(self, pubkey):
        key = base64.b64decode(pubkey.strip().split()[1].encode('ascii'))
        return hashlib.md5(key).hexdigest()

    def ex_find_or_import_keypair_by_key_material(self, pubkey, key_name=None):
        """
        Given a public key, look it up in the EC2 KeyPair database. If it
        exists, return any information we have about it. Otherwise, create it.

        Keys that are created are named based on their comment and fingerprint.

        :rtype: ``dict``
        """
        key_fingerprint = self._get_pubkey_ssh2_fingerprint(pubkey)
        key_comment = get_pubkey_comment(pubkey,
                                         default=(key_name or 'unnamed'))
        if not key_name:
            key_name = '%s-%s' % (key_comment, key_fingerprint)

        key_pairs = self.list_key_pairs(fingerprint=key_fingerprint)

        if len(key_pairs) >= 1:
            key_pair = key_pairs[0]
        else:
            key_pair = self.import_key_pair_from_string(key_name, pubkey)

        result = {
            'keyName': key_pair.name,
            'keyFingerprint': key_pair.fingerprint
        }

        return result

    def _to_key_pair(self, keys):
        name = keys['KeyName']
        public_key = keys['PublicKey']

        return KeyPair(name=name,
                       public_key=public_key,
                       fingerprint=None,
                       driver=self)

    def ex_allocate_public_ip(self, node):
        params = {}
        req = vpc_models.AllocateAddressesRequest()
        req.from_json_string(json.dumps(params))
        client = self._vpc_client(self.region)
        resp = client.AllocateAddresses(req)
        ip_address = json.loads(resp.to_json_string()).get('AddressSet', [])

        return ip_address
