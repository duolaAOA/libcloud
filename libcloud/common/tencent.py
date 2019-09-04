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

import base64
import hashlib
import hmac
import sys
import time
import random
import time

import requests

from libcloud.common.base import ConnectionUserAndKey, JsonResponse
from tencentcloud.common import credential
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.cvm.v20170312 import cvm_client, models

__all__ = [
    'TencentHTTPResponse', 'TencentRequestSigner',
    'TencentRequestSignerAlgorithmV1_0', 'SignedTencentConnection',
    'TencentConnection', 'SIGNATURE_VERSION_1_0', 'DEFAULT_SIGNATURE_VERSION'
]

SIGNATURE_VERSION_1_0 = '1.0'
DEFAULT_SIGNATURE_VERSION = SIGNATURE_VERSION_1_0


class TencentHTTPResponse(JsonResponse):
    namespace = None

    def success(self):
        return 200 <= self.status < 300


class TencentRequestSigner(object):
    """
    Class handles signing the outgoing Tencent requests.
    """

    def __init__(self, access_key, access_secret, version):
        """
        :param access_key: Access key.
        :type access_key: ``str``

        :param access_secret: Access secret.
        :type access_secret: ``str``

        :param version: API version.
        :type version: ``str``
        """
        self.access_key = access_key
        self.access_secret = access_secret
        self.version = version

    def get_request_params(self, params, method='GET', path='/'):
        return params

    def get_request_headers(self, params, headers, method='GET', path='/'):
        return params, headers


class TencentRequestSignerAlgorithmV1_0(TencentRequestSigner):
    """Tencent request signer using signature version 1.0."""

    def get_request_params(self, params, method='GET', path='/'):
        params['Nonce'] = random.randint(10000, 99999)
        params['SecretId'] = self.access_key
        params['Timestamp'] = int(time.time())
        params['Signature'] = self._sign_request(params, method, path)
        return params

    def _sign_request(self, params, method, path):
        """
        Sign Tencent requests parameters and get the signature.

        StringToSign = HTTPMethod + '&' +
                       percentEncode('/') + '&' +
                       percentEncode(CanonicalizedQueryString)
        """
        url = 'account.api.qcloud.com/v2/index.php'
        signature_old = ''
        for i in sorted(params):
            signature_old = signature_old + i + "=" + str(params[i]) + '&'
        signature_old = signature_old[:-1]
        query = method.upper() + url + '?' + signature_old

        hmac_str = hmac.new(self._get_access_secret().encode('utf8'),
                            query.encode('utf8'), hashlib.sha1).digest()

        return base64.b64encode(hmac_str)

    def _get_access_secret(self):
        return self.access_secret


class TencentConnection(ConnectionUserAndKey):
    pass


class SignedTencentConnection(TencentConnection):
    api_version = None

    def __init__(self,
                 user_id,
                 key,
                 secure=True,
                 host=None,
                 port=None,
                 url=None,
                 timeout=None,
                 proxy_url=None,
                 retry_delay=None,
                 backoff=None,
                 api_version=None,
                 signature_version=DEFAULT_SIGNATURE_VERSION):
        super(TencentConnection, self).__init__(user_id=user_id,
                                                key=key,
                                                secure=secure,
                                                host=host,
                                                port=port,
                                                url=url,
                                                timeout=timeout,
                                                proxy_url=proxy_url,
                                                retry_delay=retry_delay,
                                                backoff=backoff)

        cred = credential.Credential(self.user_id, self.key)
        self.signature_version = str(signature_version)

        if self.signature_version == '1.0':
            signer_cls = TencentRequestSignerAlgorithmV1_0
        else:
            raise ValueError('Unsupported signature_version: %s' %
                             signature_version)

        if api_version is not None:
            self.api_version = str(api_version)
        else:
            if self.api_version is None:
                raise ValueError('Unsupported null api_version')

        self.signer = cvm_client.CvmClient(cred, 'ap-beijing')

    def add_default_params(self, params):
        params = {'Action': 'DescribeProject', 'Region': 'bj', 'allList': 1}
        params = self.signer.get_request_params(params=params,
                                                method=self.method,
                                                path=self.action)
        return params


def _percent_encode(encode_str):
    """
    Encode string to utf8, quote for url and replace '+' with %20,
    '*' with %2A and keep '~' not converted.

    :param src_str: ``str`` in the same encoding with sys.stdin,
                    default to encoding cp936.
    :return: ``str`` represents the encoded result
    :rtype: ``str``
    """
    encoding = sys.stdin.encoding or 'cp936'
    decoded = str(encode_str)
    if PY3:
        if isinstance(encode_str, bytes):
            decoded = encode_str.decode(encoding)
    else:
        decoded = str(encode_str).decode(encoding)

    res = urlquote(decoded.encode('utf8'), '')
    res = res.replace('+', '%20')
    res = res.replace('*', '%2A')
    res = res.replace('%7E', '~')
    return res
