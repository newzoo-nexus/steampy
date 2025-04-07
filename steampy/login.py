from __future__ import annotations

from base64 import b64encode
from http import HTTPStatus
import time
from typing import TYPE_CHECKING

from rsa import PublicKey, encrypt
import logging
from steampy import guard
from steampy.exceptions import ApiException, CaptchaRequired, InvalidCredentials
from steampy.models import SteamUrl
from steampy.utils import create_cookie

if TYPE_CHECKING:
    from requests import Response, Session


class ApiClient:
    def __init__(self, session: Session) -> None:
        self.session = session

    def __call__(self, method: str, service: str, endpoint: str, version: str = 'v1', params: dict | None = None) -> Response:
        url = f'{SteamUrl.API_URL}/{service}/{endpoint}/{version}'
        # All requests from the login page use the same 'Referer' and 'Origin' values
        headers = {'Referer': f'{SteamUrl.COMMUNITY_URL}/', 'Origin': SteamUrl.COMMUNITY_URL}
        if method.upper() == 'GET':
            return self.session.get(url, params=params, headers=headers)
        if method.upper() == 'POST':
            return self.session.post(url, data=params, headers=headers)
        raise ValueError('Method must be either GET or POST')



class TwoFactorExecutor:
    CODE_TYPE = 3
    NUM_ATTEMPTS = 3
    FAILURE_DELAY = 30

    def __init__(self, session: Session, shared_secret: str) -> None:
        self.api_client = ApiClient(session)
        self.shared_secret = shared_secret
        self.logger = logging.getLogger(__name__)

    def __call__(self, client_id, steam_id) -> None:
        for _ in range(self.NUM_ATTEMPTS):
            eresult = self.attempt(client_id, steam_id)
            if eresult == 1:
                return
            if eresult == 88:
                self.logger.warning(f"Two factor code mismatch. Retrying in {self.FAILURE_DELAY} seconds")
                time.sleep(self.FAILURE_DELAY)
        raise Exception(f"Failed to update Steam guard after {self.NUM_ATTEMPTS} attempts")

    def attempt(self, client_id: str, steam_id: str) -> None:
        code = guard.generate_one_time_code(self.shared_secret)

        update_data = {'client_id': client_id, 'steamid': steam_id, 'code_type': self.CODE_TYPE, 'code': code}
        response = self.api_client(
            'POST', 'IAuthenticationService', 'UpdateAuthSessionWithSteamGuardCode', params=update_data,
        )
        response.raise_for_status()
        return int(response.headers.get('X-eresult'))

class AuthStatusExecutor:
    def __init__(self, session: Session) -> None:
        self.api_client = ApiClient(session)

    def __call__(self, client_id: str, request_id: str) -> None:
        pool_data = {'client_id': client_id, 'request_id': request_id}
        response = self.api_client('POST', 'IAuthenticationService', 'PollAuthSessionStatus', params=pool_data)
        data = response.json()
        eresult = response.headers.get('X-eresult')

        if 'refresh_token' not in data['response']:
            raise ApiException(
                "Credentials did not produce an authentication token. "
                f"eresult={eresult} "
                f"status_code={response.status_code} "
                f"response={response.text}"
            )
        return data['response']['refresh_token']


class LoginExecutor:
    def __init__(self, username: str, password: str, shared_secret: str, session: Session) -> None:
        self.two_factor_executor = TwoFactorExecutor(session, shared_secret)
        self.auth_status_executor = AuthStatusExecutor(session)
        self.api_client = ApiClient(session)
        self.logger = logging.getLogger(f"[{username}]{__name__}")
        self.username = username
        self.password = password
        self.one_time_code = ''
        self.shared_secret = shared_secret
        self.session = session
        self.refresh_token = ''

    def login(self) -> Session:
        login_response = self._send_login_request()
        response_body = login_response.json()
        if not response_body['response']:
            self.logger.error(
                'No response received from Steam API. Please try again later. '
                f"status_code={login_response.status_code} "
                f"response={login_response.text} "
                f"headers={login_response.headers} "
            )
            raise ApiException("No response received from Steam API. ")

        self._check_for_captcha(response_body)
        self._update_steam_guard(
            response_body["response"]['client_id'],
            response_body["response"]['steamid'],
            response_body["response"]['request_id']
        )
        finalized_response = self._finalize_login()
        self._perform_redirects(finalized_response.json())
        self.set_sessionid_cookies()
        return self.session

    def _send_login_request(self) -> Response:
        rsa_params = self._fetch_rsa_params()
        encrypted_password = self._encrypt_password(rsa_params)
        rsa_timestamp = rsa_params['rsa_timestamp']
        request_data = self._prepare_login_request_data(encrypted_password, rsa_timestamp)
        return self.api_client('POST', 'IAuthenticationService', 'BeginAuthSessionViaCredentials', params=request_data)

    def set_sessionid_cookies(self) -> None:
        community_domain = SteamUrl.COMMUNITY_URL[8:]
        store_domain = SteamUrl.STORE_URL[8:]
        community_cookie_dic = self.session.cookies.get_dict(domain=community_domain)
        store_cookie_dic = self.session.cookies.get_dict(domain=store_domain)
        for name in ('steamLoginSecure', 'sessionid', 'steamRefresh_steam', 'steamCountry'):
            cookie = self.session.cookies.get_dict()[name]
            if name == "steamLoginSecure":
                store_cookie = create_cookie(name, store_cookie_dic[name], store_domain)
            else:
                store_cookie = create_cookie(name, cookie, store_domain)

            if name in ["sessionid", "steamLoginSecure"]:
                community_cookie = create_cookie(name, community_cookie_dic[name], community_domain)
            else:
                community_cookie = create_cookie(name, cookie, community_domain)

            self.session.cookies.set(**community_cookie)
            self.session.cookies.set(**store_cookie)

    def _fetch_rsa_params(self, current_number_of_repetitions: int = 0) -> dict:
        self.session.get(SteamUrl.COMMUNITY_URL)
        request_data = {'account_name': self.username}
        response = self.api_client('GET', 'IAuthenticationService', 'GetPasswordRSAPublicKey', params=request_data)

        if response.status_code == HTTPStatus.OK and 'response' in response.json():
            key_data = response.json()['response']
            # Steam may return an empty 'response' value even if the status is 200
            if 'publickey_mod' in key_data and 'publickey_exp' in key_data and 'timestamp' in key_data:
                rsa_mod = int(key_data['publickey_mod'], 16)
                rsa_exp = int(key_data['publickey_exp'], 16)
                return {'rsa_key': PublicKey(rsa_mod, rsa_exp), 'rsa_timestamp': key_data['timestamp']}

        maximal_number_of_repetitions = 5
        if current_number_of_repetitions < maximal_number_of_repetitions:
            return self._fetch_rsa_params(current_number_of_repetitions + 1)

        raise ApiException(f'Could not obtain rsa-key. Status code: {response.status_code}')

    def _encrypt_password(self, rsa_params: dict) -> bytes:
        return b64encode(encrypt(self.password.encode('utf-8'), rsa_params['rsa_key']))

    def _prepare_login_request_data(self, encrypted_password: bytes, rsa_timestamp: str) -> dict:
        return {
            'persistence': '1',
            'encrypted_password': encrypted_password,
            'account_name': self.username,
            'encryption_timestamp': rsa_timestamp,
        }

    @staticmethod
    def _check_for_captcha(response_body) -> None:
        if response_body.get('captcha_needed', False):
            raise CaptchaRequired('Captcha required')

    @staticmethod
    def _assert_valid_credentials(login_response: Response) -> None:
        if not login_response.json()['success']:
            raise InvalidCredentials(login_response.json()['message'])

    def _perform_redirects(self, response_dict: dict) -> None:
        parameters = response_dict.get('transfer_info')
        if parameters is None:
            raise Exception('Cannot perform redirects after login, no parameters fetched')
        for pass_data in parameters:
            pass_data['params'].update({'steamID': response_dict['steamID']})
            multipart_fields = {
                key: (None, str(value))
                for key, value in pass_data['params'].items()
            }
            self.session.post(pass_data['url'], files = multipart_fields)

    def _update_steam_guard(self, client_id, steamid, request_id) -> None:
        self.two_factor_executor(client_id, steamid)
        self.refresh_token = self.auth_status_executor(client_id, request_id)

    def _finalize_login(self) -> Response:
        sessionid = self.session.cookies['sessionid']
        redir = f'{SteamUrl.COMMUNITY_URL}/login/home/?goto='
        files = {
            'nonce': (None, self.refresh_token),
            'sessionid': (None, sessionid),
            'redir': (None, redir)
        }
        headers = {
            'Referer': redir,
            'Origin': 'https://steamcommunity.com'
        }
        return self.session.post("https://login.steampowered.com/jwt/finalizelogin", headers = headers, files = files)
