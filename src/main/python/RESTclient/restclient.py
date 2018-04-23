
import os
import base64
import requests
from requests.packages.urllib3.exceptions import InsecurePlatformWarning
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import copy
import time
import logging
logger = logging.getLogger(__name__)

logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.CRITICAL)

requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def redact(kwargs):
    """ return redacted copy of dictionary
    """
    scrubbed = copy.deepcopy(kwargs)
    if 'headers' in scrubbed:
        if 'Authorization' in scrubbed['headers']:
            scrubbed['headers']['Authorization'] = '[REDACTED]'

        if 'Auth' in scrubbed['headers']:
            scrubbed['headers']['Auth'] = '[REDACTED]'

    if 'address' in scrubbed:
        del scrubbed['address']

    if 'json' in scrubbed:
        if 'password' in scrubbed['json']:
            scrubbed['json']['password'] = '[REDACTED]'

    return scrubbed


class RESTclient(object):

    cabundle = '/etc/ssl/certs/cabundle.pem'

    def __init__(self, hostname, username=None, password=None, cabundle=None):
        """ class constructor
        """
        logger.debug('executing RESTclient constructor')
        self.hostname = hostname

        if not cabundle:
            cabundle = RESTclient.cabundle
        self.cabundle = cabundle if os.access(cabundle, os.R_OK) else False

        if username:
            self.username = username

        if password:
            self.password = password

    def get_headers(self):
        """ return standard headers
        """
        headers = {
            'Content-Type': 'application/json',
        }

        if hasattr(self, 'username') and hasattr(self, 'password'):
            basic = base64.b64encode('{}:{}'.format(self.username, self.password))
            headers['Authorization'] = 'Basic {}'.format(basic)

        return headers

    def request_handler(function):
        """ returns decorator method
        """
        def _request_handler(self, *args, **kwargs):
            """ decorator method to prepare and handle requests and responses
            """
            noop = kwargs.pop('noop', False)
            standard_kwargs = self.get_standard_kwargs(args, kwargs)
            logger.debug('{}: {} NOOP: {}'.format(function.__name__.upper(), standard_kwargs['address'], noop))
            logger.debug('w/kwargs: {}'.format(redact(standard_kwargs)))
            if noop:
                return
            response = function(self, *args, **standard_kwargs)
            return self.process_response(response, **kwargs)

        return _request_handler

    def get_standard_kwargs(self, args, kwargs):
        """ set standard named arguments
        """
        processed = copy.deepcopy(kwargs)

        standard_headers = self.get_headers()
        if 'headers' not in processed:
            # set standard headers
            processed['headers'] = standard_headers
        else:
            # update headers passed in with standard headers
            processed['headers'].update(standard_headers)

        if 'verify' not in processed or processed.get('verify') is None:
            # set verify argument if not provided
            processed['verify'] = self.cabundle

        # set address named argument
        processed['address'] = 'https://{}{}'.format(self.hostname, args[0])
        return processed

    def log_response_error(self, response):
        """ log response error
        """
        json_response = response.json()
        logger.error(json_response)

    def process_response(self, response, **kwargs):
        """ process request response
        """
        if not response.ok:
            self.log_response_error(response)
            response.raise_for_status()

        try:
            return response.json()

        except ValueError:
            return response

    @request_handler
    def post(self, endpoint, **kwargs):
        """ helper method to submit post requests
        """
        return requests.post(kwargs.pop('address'), **kwargs)

    @request_handler
    def put(self, endpoint, **kwargs):
        """ helper method to submit post requests
        """
        return requests.put(kwargs.pop('address'), **kwargs)

    @request_handler
    def get(self, endpoint, **kwargs):
        """ helper method to submit get requests
        """
        return requests.get(kwargs.pop('address'), **kwargs)

    @request_handler
    def delete(self, endpoint, **kwargs):
        """ helper method to submit delete requests
        """
        return requests.delete(kwargs.pop('address'), **kwargs)

    request_handler = staticmethod(request_handler)
