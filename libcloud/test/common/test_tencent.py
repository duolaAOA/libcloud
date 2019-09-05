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
import unittest

from libcloud.common import tencent
from libcloud.common.tencent import TencentRequestSignerAlgorithmV1_0
from libcloud.test import LibcloudTestCase


class TencentRequestSignerAlgorithmV1_0TestCase(LibcloudTestCase):
    def setUp(self):
        self.signer = TencentRequestSignerAlgorithmV1_0(
            'testid', 'testsecret', '1.0')

    def test_sign_request(self):
        params = {
            'TimeStamp': '2012-12-26T10:33:56Z',
            'Format': 'XML',
            'AccessKeyId': 'testid',
            'Action': 'DescribeRegions',
            'SignatureMethod': 'HMAC-SHA1',
            'RegionId': 'region1',
            'SignatureNonce': 'NwDAxvLU6tFE0DVb',
            'Version': '2014-05-26',
            'SignatureVersion': '1.0'
        }
        method = 'GET'
        path = '/'

        expected = b'eJtVU6T+sXl6kU1Ti3UaFxgn+Rs='
        self.assertEqual(expected,
                         self.signer._sign_request(params, method, path))


class TencentCommonTestCase(LibcloudTestCase):
    def test_percent_encode(self):
        data = {'abc': 'abc', ' *~': '%20%2A~'}
        for key in data:
            self.assertEqual(data[key], tencent._percent_encode(key))


if __name__ == '__main__':
    sys.exit(unittest.main())
