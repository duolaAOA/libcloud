from libcloud.utils.py3 import httplib

from libcloud.common.types import InvalidCredsError
from libcloud.common.base import JsonResponse
from libcloud.common.base import ConnectionKey


class ClearVmResponse(JsonResponse):
    valid_response_codes = [httplib.OK, httplib.ACCEPTED, httplib.CREATED,
                            httplib.NO_CONTENT]

    def parse_error(self):
        if self.status == httplib.UNAUTHORIZED:
            body = self.parse_body()
            raise InvalidCredsError(body['message'])
        else:
            body = self.parse_body()
            if 'message' in body:
                error = '%s (code: %s)' % (body['message'], self.status)
            else:
                error = body
            return error

    def success(self):
        return self.status in self.valid_response_codes


class ClearVmConnection(ConnectionKey):
    """
    Connection class for the ClearVm driver.
    """

    responseCls = ClearVmResponse

    def add_default_headers(self, headers):
        """
        Add headers that are necessary for every request

        This method adds apikey to the request.
        """
	import ipdb; ipdb.set_trace();
        headers['X-Authorization'] = 'Bearer %s' % (self.key)
        headers['Content-Type'] = 'application/json'
        return headers
