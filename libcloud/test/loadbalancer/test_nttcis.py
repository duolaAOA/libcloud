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
import sys
import pytest
from libcloud.utils.py3 import httplib

from libcloud.common.types import InvalidCredsError
from libcloud.common.nttcis import NttCisVIPNode, NttCisPool
from libcloud.common.nttcis import NttCisPoolMember
from libcloud.loadbalancer.base import LoadBalancer, Member, Algorithm
from libcloud.loadbalancer.drivers.nttcis import NttCisLBDriver as NttCis
from libcloud.loadbalancer.types import State

from libcloud.test import MockHttp, unittest
from libcloud.test.file_fixtures import LoadBalancerFileFixtures

from libcloud.test.secrets import NTTCIS_PARAMS


@pytest.fixture()
def driver():
    NttCis.connectionCls.active_api_version = "2.7"
    NttCis.connectionCls.conn_class = NttCisMockHttp
    NttCisMockHttp.type = None
    driver = NttCis(*NTTCIS_PARAMS)
    return driver


def test_invalid_region(driver):
    with pytest.raises(ValueError):
        driver = NttCis(*NTTCIS_PARAMS, region='blah')


def test_invalid_creds(driver):
    NttCisMockHttp.type = 'UNAUTHORIZED'
    with pytest.raises(InvalidCredsError):
        driver.list_balancers()


def test_create_balancer(driver, capsys):
    print(Algorithm.ROUND_ROBIN)
    driver.ex_set_current_network_domain('1234')
    members = []
    members.append(Member(id=None, ip='1.2.3.4', port=80))

    balancer = driver.create_balancer(
                                      name='test',
                                      port=80,
                                      protocol='http',
                                      optimization_profile='TCP',
                                      algorithm=Algorithm.ROUND_ROBIN,
                                      members=members,
                                      ex_listener_ip_address='5.6.7.8')
    assert balancer.name == 'test'
    assert balancer.id == '8334f461-0df0-42d5-97eb-f4678eb26bea'
    assert balancer.ip == '165.180.12.22'
    assert balancer.port == 80
    assert balancer.extra['pool_id'] == '9e6b496d-5261-4542-91aa-b50c7f569c54'
    assert balancer.extra['network_domain_id'] == '1234'
    assert balancer.extra['listener_ip_address'] == '5.6.7.8'


def test_create_balancer_with_defaults(driver):
    driver.ex_set_current_network_domain('1234')

    balancer = driver.create_balancer(name='test',
                                      port=None,
                                      protocol=None,
                                      algorithm=None,
                                      members=None)
    assert balancer.name == 'test'
    assert balancer.id == '8334f461-0df0-42d5-97eb-f4678eb26bea'
    assert balancer.ip == '165.180.12.22'
    assert balancer.port is None
    assert balancer.extra['pool_id'] == '9e6b496d-5261-4542-91aa-b50c7f569c54'
    assert balancer.extra['network_domain_id'] == '1234'


def test_create_balancer_no_members(driver):
    driver.ex_set_current_network_domain('1234')
    members = None

    balancer = driver.create_balancer(
                                      name='test',
                                      port=80,
                                      protocol='http',
                                      algorithm=Algorithm.ROUND_ROBIN,
                                      members=members)
    assert balancer.name == 'test'
    assert balancer.id == '8334f461-0df0-42d5-97eb-f4678eb26bea'
    assert balancer.ip == '165.180.12.22'
    assert balancer.port == 80
    assert balancer.extra['pool_id'] == '9e6b496d-5261-4542-91aa-b50c7f569c54'
    assert balancer.extra['network_domain_id'] == '1234'


def test_create_balancer_empty_members(driver):
    driver.ex_set_current_network_domain('1234')
    members = []

    balancer = driver.create_balancer(
                                      name='test',
                                      port=80,
                                      protocol='http',
                                      algorithm=Algorithm.ROUND_ROBIN,
                                      members=members)
    assert balancer.name == 'test'
    assert balancer.id == '8334f461-0df0-42d5-97eb-f4678eb26bea'
    assert balancer.ip == '165.180.12.22'
    assert balancer.port == 80
    assert balancer.extra['pool_id'] == '9e6b496d-5261-4542-91aa-b50c7f569c54'
    assert balancer.extra['network_domain_id'] == '1234'


def test_list_balancers(driver):
    bal = driver.list_balancers()
    assert bal[0].name == 'myProduction.Virtual.Listener'
    assert bal[0].id == '6115469d-a8bb-445b-bb23-d23b5283f2b9'
    assert bal[0].port == '8899'
    assert bal[0].ip == '165.180.12.22'
    assert bal[0].state == State.RUNNING


def test_balancer_list_members(driver):
    extra = {'pool_id': '4d360b1f-bc2c-4ab7-9884-1f03ba2768f7',
             'network_domain_id': '1234'}
    balancer = LoadBalancer(
                            id='234',
                            name='test',
                            state=State.RUNNING,
                            ip='1.2.3.4',
                            port=1234,
                            driver=driver,
                            extra=extra
                           )
    members = driver.balancer_list_members(balancer)
    assert 2 == len(members)
    assert members[0].ip ==  '10.0.3.13'
    assert members[0].id == '3dd806a2-c2c8-4c0c-9a4f-5219ea9266c0'
    assert members[0].port == 9889


def test_balancer_attach_member(driver):
    extra = {'pool_id': '4d360b1f-bc2c-4ab7-9884-1f03ba2768f7',
             'network_domain_id': '1234'}
    balancer = LoadBalancer(
                            id='234',
                            name='test',
                            state=State.RUNNING,
                            ip='1.2.3.4',
                            port=1234,
                            driver=driver,
                            extra=extra
                          )
    member = Member(id=None, ip='112.12.2.2', port=80, balancer=balancer, extra=None)
    member = driver.balancer_attach_member(balancer, member)
    assert member.id == '3dd806a2-c2c8-4c0c-9a4f-5219ea9266c0'


def test_balancer_attach_member_without_port(driver):
    extra = {'pool_id': '4d360b1f-bc2c-4ab7-9884-1f03ba2768f7',
             'network_domain_id': '1234'}
    balancer = LoadBalancer(
                            id='234',
                            name='test',
                            state=State.RUNNING,
                            ip='1.2.3.4',
                            port=1234,
                            driver=driver,
                            extra=extra
                        )
    member = Member(id=None,
                    ip='112.12.2.2',
                    port=None,
                    balancer=balancer,
                    extra=None)
    member = driver.balancer_attach_member(balancer, member)
    assert member.id == '3dd806a2-c2c8-4c0c-9a4f-5219ea9266c0'
    assert member.port == None


def test_balancer_detach_member(driver):
    extra = {'pool_id': '4d360b1f-bc2c-4ab7-9884-1f03ba2768f7',
             'network_domain_id': '1234'}
    balancer = LoadBalancer(
                            id='234',
                            name='test',
                            state=State.RUNNING,
                            ip='1.2.3.4',
                            port=1234,
                            driver=driver,
                            extra=extra
                          )
    member = Member(
                    id='3dd806a2-c2c8-4c0c-9a4f-5219ea9266c0',
                    ip='112.12.2.2',
                    port=80,
                    balancer=balancer,
                    extra=None
                   )
    result = driver.balancer_detach_member(balancer, member)
    assert result, True


def test_destroy_balancer(driver):
    extra = {'pool_id': '4d360b1f-bc2c-4ab7-9884-1f03ba2768f7',
             'network_domain_id': '1234'}
    balancer = LoadBalancer(
                            id='234',
                            name='test',
                            state=State.RUNNING,
                            ip='1.2.3.4',
                            port=1234,
                            driver=driver,
                            extra=extra
                          )
    response = driver.destroy_balancer(balancer)
    assert response is True


def test_set_get_network_domain_id(driver):
    driver.ex_set_current_network_domain('1234')
    nwd = driver.ex_get_current_network_domain()
    assert nwd == '1234'


def test_ex_create_pool_member(driver):
    pool = NttCisPool(
                      id='4d360b1f-bc2c-4ab7-9884-1f03ba2768f7',
                      name='test',
                      description='test',
                      status=State.RUNNING,
                      health_monitor_id=None,
                      load_balance_method=None,
                      service_down_action=None,
                      slow_ramp_time=None
                    )
    node = NttCisVIPNode(
                        id='2344',
                        name='test',
                        status=State.RUNNING,
                        ip='123.23.3.2'
                       )
    member = driver.ex_create_pool_member(pool=pool, node=node, port=80)
    assert member.id == '3dd806a2-c2c8-4c0c-9a4f-5219ea9266c0'
    assert member.name == '10.0.3.13'
    assert member.ip == '123.23.3.2'


def test_ex_create_node(driver):
    node = driver.ex_create_node(
                                 network_domain_id='12345',
                                 name='test',
                                 ip='123.12.32.2',
                                 ex_description='',
                                 connection_limit=25000,
                                 connection_rate_limit=2000)
    assert node.name == 'myProductionNode.1'
    assert node.id == '9e6b496d-5261-4542-91aa-b50c7f569c54'


def test_ex_create_pool(driver, ):
    pool = driver.ex_create_pool(
                                 network_domain_id='1234',
                                 name='test',
                                 balancer_method='ROUND_ROBIN',
                                 ex_description='test',
                                 service_down_action='NONE',
                                 slow_ramp_time=30)
    assert pool.id == '9e6b496d-5261-4542-91aa-b50c7f569c54'
    assert pool.name == 'test'
    assert pool.status == State.RUNNING


def test_ex_create_virtual_listener(driver):
    listener = driver.ex_create_virtual_listener(
        network_domain_id='12345',
        name='test',
        ex_description='test',
        port=80,
        pool=NttCisPool(
                        id='1234',
                        name='test',
                        description='test',
                        status=State.RUNNING,
                        health_monitor_id=None,
                        load_balance_method=None,
                        service_down_action=None,
                        slow_ramp_time=None
                    ))
    assert listener.id == '8334f461-0df0-42d5-97eb-f4678eb26bea'
    assert listener.name == 'test'


def test_ex_create_virtual_listener_unusual_port(driver):
    listener = driver.ex_create_virtual_listener(
        network_domain_id='12345',
        name='test',
        ex_description='test',
        port=8900,
        pool=NttCisPool(
                        id='1234',
                        name='test',
                        description='test',
                        status=State.RUNNING,
                        health_monitor_id=None,
                        load_balance_method=None,
                        service_down_action=None,
                        slow_ramp_time=None
                       ))
    assert listener.id == '8334f461-0df0-42d5-97eb-f4678eb26bea'
    assert listener.name == 'test'


def test_ex_create_virtual_listener_without_port(driver):
    listener = driver.ex_create_virtual_listener(
            network_domain_id='12345',
        name='test',
        ex_description='test',
        pool=NttCisPool(
                        id='1234',
                        name='test',
                        description='test',
                        status=State.RUNNING,
                        health_monitor_id=None,
                        load_balance_method=None,
                        service_down_action=None,
                        slow_ramp_time=None
                       ))
    assert listener.id == '8334f461-0df0-42d5-97eb-f4678eb26bea'
    assert listener.name == 'test'


def test_ex_create_virtual_listener_without_pool(driver):
    listener = driver.ex_create_virtual_listener(
                                                 network_domain_id='12345',
                                                 name='test',
                                                 ex_description='test')
    assert listener.id == '8334f461-0df0-42d5-97eb-f4678eb26bea'
    assert listener.name == 'test'


def test_get_balancer(driver):
    bal = driver.get_balancer('6115469d-a8bb-445b-bb23-d23b5283f2b9')
    assert bal.name == 'myProduction.Virtual.Listener'
    assert bal.id == '6115469d-a8bb-445b-bb23-d23b5283f2b9'
    assert bal.port == '8899'
    assert bal.ip == '165.180.12.22'
    assert bal.state == State.RUNNING


def test_list_protocols(driver):
    protocols = driver.list_protocols()
    assert 0 < len(protocols)


def test_ex_get_nodes(driver):
    nodes = driver.ex_get_nodes()
    assert 2 == len(nodes)
    assert nodes[0].name == 'ProductionNode.1'
    assert nodes[0].id == '34de6ed6-46a4-4dae-a753-2f8d3840c6f9'
    assert nodes[0].ip == '10.10.10.101'


def test_ex_get_node(driver):
    node = driver.ex_get_node('34de6ed6-46a4-4dae-a753-2f8d3840c6f9')
    assert node.name == 'ProductionNode.2'
    assert node.id == '34de6ed6-46a4-4dae-a753-2f8d3840c6f9'
    assert node.ip == '10.10.10.101'


def test_ex_update_node(driver):
    node = driver.ex_get_node('34de6ed6-46a4-4dae-a753-2f8d3840c6f9')
    node.connection_limit = '100'
    result = driver.ex_update_node(node)
    assert result.connection_limit == '100'


def test_ex_destroy_node(driver):
    result = driver.ex_destroy_node('34de6ed6-46a4-4dae-a753-2f8d3840c6f9')
    assert result is True


def test_ex_set_node_state(driver):
    node = driver.ex_get_node('34de6ed6-46a4-4dae-a753-2f8d3840c6f9')
    result = driver.ex_set_node_state(node, False)
    assert result.connection_limit == '10000'


def test_ex_get_pools(driver):
    pools = driver.ex_get_pools()
    assert 0 != len(pools)
    assert pools[0].name == 'myDevelopmentPool.1'
    assert pools[0].id == '4d360b1f-bc2c-4ab7-9884-1f03ba2768f7'


def test_ex_get_pool(driver):
    pool = driver.ex_get_pool('4d360b1f-bc2c-4ab7-9884-1f03ba2768f7')
    assert pool.name == 'myDevelopmentPool.1'
    assert pool.id == '4d360b1f-bc2c-4ab7-9884-1f03ba2768f7'


def test_ex_update_pool(driver):
    pool = driver.ex_get_pool('4d360b1f-bc2c-4ab7-9884-1f03ba2768f7')
    pool.slow_ramp_time = '120'
    result = driver.ex_update_pool(pool)
    assert result is True


def test_ex_destroy_pool(driver):
    response = driver.ex_destroy_pool(
        pool=NttCisPool(
                        id='4d360b1f-bc2c-4ab7-9884-1f03ba2768f7',
                        name='test',
                        description='test',
                        status=State.RUNNING,
                        health_monitor_id=None,
                        load_balance_method=None,
                        service_down_action=None,
                        slow_ramp_time=None))
    assert response is True


def test_get_pool_members(driver):
    members = driver.ex_get_pool_members('4d360b1f-bc2c-4ab7-9884-1f03ba2768f7')
    assert 2 == len(members)
    assert members[0].id == '3dd806a2-c2c8-4c0c-9a4f-5219ea9266c0'
    assert members[0].name == '10.0.3.13'
    assert members[0].status == 'NORMAL'
    assert members[0].ip == '10.0.3.13'
    assert members[0].port == 9889
    assert members[0].node_id == '3c207269-e75e-11e4-811f-005056806999'


def test_get_pool_member(driver):
    member = driver.ex_get_pool_member('3dd806a2-c2c8-4c0c-9a4f-5219ea9266c0')
    assert member.id == '3dd806a2-c2c8-4c0c-9a4f-5219ea9266c0'
    assert member.name == '10.0.3.13'
    assert member.status == 'NORMAL'
    assert member.ip == '10.0.3.13'
    assert member.port == 9889


def test_set_pool_member_state(driver):
    member = driver.ex_get_pool_member('3dd806a2-c2c8-4c0c-9a4f-5219ea9266c0')
    result = driver.ex_set_pool_member_state(member, True)
    assert result is True


def test_ex_destroy_pool_member(driver):
    response = driver.ex_destroy_pool_member(member=NttCisPoolMember(
                                                                     id='',
                                                                     name='test',
                                                                     status=State.RUNNING,
                                                                     ip='1.2.3.4',
                                                                     port=80,
                                                                     node_id='3c207269-e75e-11e4-811f-005056806999'),
                                             destroy_node=False)
    assert response is True


def test_ex_destroy_pool_member_with_node(driver):
    response = driver.ex_destroy_pool_member(
                                             member=NttCisPoolMember(
                                                                     id='',
                                                                     name='test',
                                                                     status=State.RUNNING,
                                                                     ip='1.2.3.4',
                                                                     port=80,
                                                                     node_id='34de6ed6-46a4-4dae-a753-2f8d3840c6f9'),
                                            destroy_node=True)
    assert response is True


def test_ex_get_default_health_monitors(driver):
    monitors = driver.ex_get_default_health_monitors(
        '4d360b1f-bc2c-4ab7-9884-1f03ba2768f7'
    )
    assert len(monitors) == 6
    assert monitors[0].id == '01683574-d487-11e4-811f-005056806999'
    assert monitors[0].name == 'CCDEFAULT.Http'
    assert monitors[0].node_compatible is False
    assert monitors[0].pool_compatible is True


def test_ex_get_default_persistence_profiles(driver):
    profiles = driver.ex_get_default_persistence_profiles(
        '4d360b1f-bc2c-4ab7-9884-1f03ba2768f7'
    )
    assert len(profiles) == 4
    assert profiles[0].id == 'a34ca024-f3db-11e4-b010-005056806999'
    assert profiles[0].name == 'CCDEFAULT.Cookie'
    assert profiles[0].fallback_compatible is False
    assert len(profiles[0].compatible_listeners) == 1
    assert profiles[0].compatible_listeners[0].type == 'PERFORMANCE_LAYER_4'


def test_ex_get_default_irules(driver):
    irules = driver.ex_get_default_irules(
        '4d360b1f-bc2c-4ab7-9884-1f03ba2768f7'
    )
    assert len(irules) == 4
    assert irules[0].id == '2b20cb2c-ffdc-11e4-b010-005056806999'
    assert irules[0].name == 'CCDEFAULT.HttpsRedirect'
    assert len(irules[0].compatible_listeners) == 1
    assert irules[0].compatible_listeners[0].type == 'PERFORMANCE_LAYER_4'


class NttCisMockHttp(MockHttp):

    fixtures = LoadBalancerFileFixtures('nttcis')

    def _oec_0_9_myaccount_UNAUTHORIZED(self, method, url, body, headers):
        return (httplib.UNAUTHORIZED, "", {}, httplib.responses[httplib.UNAUTHORIZED])

    def _oec_0_9_myaccount(self, method, url, body, headers):
        body = self.fixtures.load('oec_0_9_myaccount.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _oec_0_9_myaccount_INPROGRESS(self, method, url, body, headers):
        body = self.fixtures.load('oec_0_9_myaccount.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_virtualListener(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_virtualListener.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_virtualListener_6115469d_a8bb_445b_bb23_d23b5283f2b9(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_virtualListener_6115469d_a8bb_445b_bb23_d23b5283f2b9.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_pool(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_pool.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_pool_4d360b1f_bc2c_4ab7_9884_1f03ba2768f7(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_pool_4d360b1f_bc2c_4ab7_9884_1f03ba2768f7.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_poolMember(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_poolMember.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_poolMember_3dd806a2_c2c8_4c0c_9a4f_5219ea9266c0(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_poolMember_3dd806a2_c2c8_4c0c_9a4f_5219ea9266c0.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_createPool(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_createPool.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_createNode(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_createNode.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_addPoolMember(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_addPoolMember.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_createVirtualListener(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_createVirtualListener.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_removePoolMember(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_removePoolMember.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_deleteVirtualListener(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_deleteVirtualListener.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_deletePool(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_deletePool.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_deleteNode(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_deleteNode.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_node(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_node.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_node_34de6ed6_46a4_4dae_a753_2f8d3840c6f9(self,  method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_node_34de6ed6_46a4_4dae_a753_2f8d3840c6f9.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_editNode(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_editNode.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_editPool(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_editPool.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_editPoolMember(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_editPoolMember.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_defaultHealthMonitor(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_defaultHealthMonitor.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_defaultPersistenceProfile(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_defaultPersistenceProfile.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _caas_2_7_8a8f6abc_2745_4d8a_9cbc_8dabe5a7d0e4_networkDomainVip_defaultIrule(self, method, url, body, headers):
        body = self.fixtures.load(
            'networkDomainVip_defaultIrule.xml')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

if __name__ == '__main__':
    sys.exit(unittest.main())
