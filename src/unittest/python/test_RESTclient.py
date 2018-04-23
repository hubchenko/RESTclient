
import unittest
from mock import patch
from mock import mock_open
from mock import call
from mock import Mock
# from mock import PropertyMock

from RESTclient import RESTclient
from RESTclient.restclient import redact

import sys
import logging
logger = logging.getLogger(__name__)

consoleHandler = logging.StreamHandler(sys.stdout)
logFormatter = logging.Formatter(
    "%(asctime)s %(threadName)s %(name)s [%(funcName)s] %(levelname)s %(message)s")
consoleHandler.setFormatter(logFormatter)
rootLogger = logging.getLogger()
rootLogger.addHandler(consoleHandler)
rootLogger.setLevel(logging.DEBUG)


class TestRESTclient(unittest.TestCase):

    def setUp(self):
        """
        """
        pass

    def tearDown(self):
        """
        """
        pass

    @patch('RESTclient.restclient.os.access', return_value=True)
    def test__init__Should_SetAttributes_When_CabundleExists(self, *patches):
        hostname = 'server.fm.intel.com'
        cabundle = 'cabundle'
        client = RESTclient(hostname, cabundle=cabundle)
        self.assertEqual(client.hostname, hostname)
        self.assertEqual(client.cabundle, cabundle)

    @patch('RESTclient.restclient.os.access', return_value=False)
    def test__init__Should_SetAttributes_When_CabundleDoesNotExist(self, *patches):
        hostname = 'server.fm.intel.com'
        cabundle = 'cabundle'
        client = RESTclient(hostname, cabundle=cabundle)
        self.assertEqual(client.hostname, hostname)
        self.assertFalse(client.cabundle)

    @patch('RESTclient.restclient.os.access')
    def test__get_headers_Should_ReturnHeaders_When_Called(self, *patches):
        client = RESTclient('server.fm.intel.com')
        result = client.get_headers()
        expected_result = {
            'Content-Type': 'application/json',
        }
        self.assertEqual(result, expected_result)

    @patch('RESTclient.restclient.os.access')
    def test__request_handler_Should_CallFunctionWithArgs_When_Args(self, *patches):
        mock_function = Mock(__name__='mocked method')
        client = RESTclient('server.fm.intel.com')
        decorated_function = RESTclient.request_handler(mock_function)
        decorated_function(client, '/rest/endpoint', 'arg1', 'arg2')
        expected_args = (client, '/rest/endpoint', 'arg1', 'arg2')
        args, _ = mock_function.call_args_list[0]
        self.assertEqual(args, expected_args)

    @patch('RESTclient.restclient.os.access')
    @patch('RESTclient.RESTclient.get_headers')
    def test__request_handler_Should_CallFunctionWithKwargs_When_Kwargs(self, get_headers, *patches):
        get_headers.return_value = {'h1': 'v1'}
        mock_function = Mock(__name__='mocked method')
        client = RESTclient('server.fm.intel.com')
        decorated_function = RESTclient.request_handler(mock_function)
        decorated_function(client, '/rest/endpoint', kwarg1='kwarg1', kwarg2='kwarg2', verify=False)
        expected_kwargs = {
            'headers': {
                'h1': 'v1'
            },
            'verify': False,
            'address': 'https://server.fm.intel.com/rest/endpoint',
            'kwarg1': 'kwarg1',
            'kwarg2': 'kwarg2'
        }
        _, kwargs = mock_function.call_args_list[0]
        self.assertEqual(kwargs, expected_kwargs)

    @patch('RESTclient.restclient.os.access')
    @patch('RESTclient.RESTclient.get_standard_kwargs')
    @patch('RESTclient.RESTclient.process_response', return_value='result')
    def test__request_handler_Should_CallFunctionAndReturnResult_When_FunctionDoesNotSetNoop(self, *patches):
        mock_function = Mock(__name__='mocked method')
        client = RESTclient('server.fm.intel.com')
        decorated_function = RESTclient.request_handler(mock_function)
        result = decorated_function(client, '/rest/endpoint')
        self.assertTrue(mock_function.called)
        self.assertEqual(result, 'result')

    @patch('RESTclient.restclient.os.access')
    @patch('RESTclient.RESTclient.get_standard_kwargs')
    @patch('RESTclient.RESTclient.process_response')
    def test__request_handler_Should_NotCallFunctionAndReturnNone_When_FunctionSetsNoop(self, *patches):
        mock_function = Mock(__name__='mocked method')
        client = RESTclient('server.fm.intel.com')
        decorated_function = RESTclient.request_handler(mock_function)
        result = decorated_function(client, '/rest/endpoint', noop=True)
        self.assertIsNone(result)
        self.assertFalse(mock_function.called)

    @patch('RESTclient.restclient.os.access')
    @patch('RESTclient.RESTclient.get_headers', return_value={'h1': 'v1'})
    def test__get_standard_kwargs_Should_SetHeaders_When_NoHeadersSpecified(self, *patches):
        client = RESTclient('server.fm.intel.com')
        args = ['/endpoint']
        kwargs = {}
        result = client.get_standard_kwargs(args, kwargs)
        expected_result = {
            'h1': 'v1'
        }
        self.assertEqual(result['headers'], expected_result)

    @patch('RESTclient.restclient.os.access')
    @patch('RESTclient.RESTclient.get_headers', return_value={'h1': 'v1'})
    def test__get_standard_kwargs_Should_UpdatedHeaders_When_HeadersSpecified(self, *patches):
        client = RESTclient('server.fm.intel.com')
        args = ['/endpoint']
        kwargs = {
            'headers': {
                'h2': 'v2'
            }
        }
        result = client.get_standard_kwargs(args, kwargs)
        expected_result = {
            'h1': 'v1',
            'h2': 'v2'
        }
        self.assertEqual(result['headers'], expected_result)

    @patch('RESTclient.restclient.os.access')
    @patch('RESTclient.RESTclient.get_headers', return_value={'h1': 'v1'})
    def test__get_standard_kwargs_Should_SetVerifyToCabundle_When_VerifyNotSpecified(self, *patches):
        client = RESTclient('server.fm.intel.com')
        args = ['/endpoint']
        kwargs = {}
        result = client.get_standard_kwargs(args, kwargs)
        self.assertEqual(result['verify'], client.cabundle)

    @patch('RESTclient.restclient.os.access')
    @patch('RESTclient.RESTclient.get_headers', return_value={'h1': 'v1'})
    def test__get_standard_kwargs_Should_SetVerifyToCabundle_When_VerifyIsNone(self, *patches):
        client = RESTclient('server.fm.intel.com')
        args = ['/endpoint']
        kwargs = {
            'verify': None
        }
        result = client.get_standard_kwargs(args, kwargs)
        self.assertEqual(result['verify'], client.cabundle)

    @patch('RESTclient.restclient.os.access')
    @patch('RESTclient.RESTclient.get_headers', return_value={'h1': 'v1'})
    def test__get_standard_kwargs_Should_NotSetVerify_When_VerifyIsSet(self, *patches):
        client = RESTclient('server.fm.intel.com')
        args = ['/endpoint']
        kwargs = {
            'verify': False
        }
        result = client.get_standard_kwargs(args, kwargs)
        self.assertFalse(result['verify'])

    @patch('RESTclient.restclient.os.access')
    @patch('RESTclient.RESTclient.get_headers', return_value={'h1': 'v1'})
    def test__get_standard_kwargs_Should_SetAddress_When_Called(self, *patches):
        client = RESTclient('server.fm.intel.com')
        args = ['/endpoint']
        kwargs = {}
        result = client.get_standard_kwargs(args, kwargs)
        expected_result = 'https://server.fm.intel.com/endpoint'
        self.assertEqual(result['address'], expected_result)

    @patch('RESTclient.restclient.os.access')
    def test__process_response_Should_ReturnResponseJson_When_ResponseOk(self, *patches):
        mock_response = Mock(ok=True)
        mock_response.json.return_value = {
            'result': 'result'
        }
        client = RESTclient('server.fm.intel.com')
        result = client.process_response(mock_response)
        self.assertEqual(result, mock_response.json.return_value)

    @patch('RESTclient.restclient.os.access')
    def test__process_response_Should_CallResponseRaiseForStatus_When_ResponseNotOk(self, *patches):
        mock_response = Mock(ok=False)
        mock_response.json.return_value = {
            'message': 'error message',
            'details': 'error details'}
        mock_response.raise_for_status.side_effect = [
            Exception('exception occurred')
        ]

        client = RESTclient('server.fm.intel.com')
        with self.assertRaises(Exception):
            client.process_response(mock_response)

    @patch('RESTclient.restclient.os.access')
    @patch('RESTclient.restclient.requests')
    def test__get_Should_CallRequestsGet_When_Called(self, requests, *patches):
        client = RESTclient('server.fm.intel.com')
        client.get('/rest/endpoint')
        requests_get_call = call(
            'https://server.fm.intel.com/rest/endpoint',
            headers={
                'Content-Type': 'application/json'},
            verify=client.cabundle)
        self.assertEqual(requests.get.mock_calls[0], requests_get_call)

    @patch('RESTclient.restclient.os.access')
    @patch('RESTclient.restclient.requests')
    def test__post_Should_CallRequestsPost_When_Called(self, requests, *patches):
        client = RESTclient('server.fm.intel.com')
        requests_data = {
            'arg1': 'val1',
            'arg2': 'val2'}
        client.post('/rest/endpoint', json=requests_data)
        requests_post_call = call(
            'https://server.fm.intel.com/rest/endpoint',
            headers={
                'Content-Type': 'application/json'},
            json={
                'arg1': 'val1',
                'arg2': 'val2'},
            verify=client.cabundle)
        self.assertEqual(requests.post.mock_calls[0], requests_post_call)

    @patch('RESTclient.restclient.os.access')
    @patch('RESTclient.restclient.requests')
    def test__put_Should_CallRequestsPut_When_Called(self, requests, *patches):
        client = RESTclient('server.fm.intel.com')
        requests_data = {
            'arg1': 'val1',
            'arg2': 'val2'}
        client.put('/rest/endpoint', json=requests_data)
        requests_put_call = call(
            'https://server.fm.intel.com/rest/endpoint',
            headers={
                'Content-Type': 'application/json'},
            json={
                'arg1': 'val1',
                'arg2': 'val2'},
            verify=client.cabundle)
        self.assertEqual(requests.put.mock_calls[0], requests_put_call)

    @patch('RESTclient.restclient.os.access')
    @patch('RESTclient.restclient.requests')
    def test__delete_Should_CallRequestsDelete_When_Called(self, requests, *patches):
        client = RESTclient(hostname='server.fm.intel.com')
        client.delete('/rest/endpoint')
        requests_delete_call = call(
            'https://server.fm.intel.com/rest/endpoint',
            headers={
                'Content-Type': 'application/json'},
            verify=client.cabundle)
        self.assertEqual(requests.delete.mock_calls[0], requests_delete_call)

    @patch('RESTclient.restclient.os.access', return_value=False)
    def test__init__Should_SetUsernamePasswordAttributes_When_CalledWithUsernamePassword(self, *patches):
        client = RESTclient('hostname', username='value1', password='value2')
        self.assertEqual(client.username, 'value1')
        self.assertEqual(client.password, 'value2')

    @patch('RESTclient.restclient.os.access', return_value=False)
    def test__get_headers_Should_SetAuthorizationHeader_When_UsernamePasswordAttributesExist(self, *patches):
        client = RESTclient('hostname', username='value1', password='value2')
        results = client.get_headers()
        self.assertTrue('Authorization' in results)
        self.assertTrue('Basic' in results['Authorization'])

    @patch('RESTclient.restclient.os.access')
    def test__process_response_Should_ReturnResponseText_When_ResponseJsonRaisesValueError(self, *patches):
        mock_response = Mock(ok=True, text='response text')
        mock_response.json.side_effect = [
            ValueError('No JSON')
        ]
        client = RESTclient('server.fm.intel.com')
        result = client.process_response(mock_response)
        self.assertEqual(result, mock_response)

    def test__redact_Should_Redact_When_AuthorizationInHeaders(self, *patches):
        headers = {
            'headers': {
                'Content-Type': 'application/json',
                'Authorization': 'Basic abcdefghijklmnopqrstuvwxyz'
            },
            'address': 'Address',
            'verify': 'verify'
        }
        result = redact(headers)
        expected_result = {
            'headers': {
                'Content-Type': 'application/json',
                'Authorization': '[REDACTED]'
            },
            'verify': 'verify'
        }
        self.assertEqual(result, expected_result)

    def test__redact_Should_Redact_When_AuthInHeaders(self, *patches):
        headers = {
            'headers': {
                'Content-Type': 'application/json',
                'Auth': 'SessionToken'
            },
            'address': 'Address',
            'verify': 'verify'
        }
        result = redact(headers)
        expected_result = {
            'headers': {
                'Content-Type': 'application/json',
                'Auth': '[REDACTED]'
            },
            'verify': 'verify'
        }
        self.assertEqual(result, expected_result)

    def test__redact_Should_Redact_When_JsonPassword(self, *patches):
        headers = {
            'headers': {
                'Content-Type': 'application/json',
                'Auth': 'SessionToken'
            },
            'address': 'Address',
            'verify': 'verify',
            'json': {
                'userName': 'some user',
                'password': 'some password'
            }
        }
        result = redact(headers)
        expected_result = {
            'headers': {
                'Content-Type': 'application/json',
                'Auth': '[REDACTED]'
            },
            'verify': 'verify',
            'json': {
                'userName': 'some user',
                'password': '[REDACTED]'
            }
        }
        self.assertEqual(result, expected_result)
