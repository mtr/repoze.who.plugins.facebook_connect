# -*- coding: utf-8 -*-

import base64
import hmac
from collections import namedtuple
from httplib import FOUND, BAD_REQUEST

from repoze.who.interfaces import IIdentifier, IAuthenticator
from webob import Request, Response as WebObResponse
from zope.interface import implements

try:
    import cPickle as pickle
except ImportError:
    import pickle
try:
    from hashlib import sha1
except ImportError:
    import sha as sha1

from facebook import get_user_from_cookie, GraphAPI, GraphAPIError, auth_url

FACEBOOK_CONNECT_REPOZE_WHO_ID_KEY = 'repoze.who.facebook_connect.userid'
FACEBOOK_CONNECT_REPOZE_WHO_MISSING_MANDATORY = \
    'repoze.who.facebook_connect.missing_mandatory'
FACEBOOK_CONNECT_REPOZE_WHO_MISSING_OPTIONAL = \
    'repoze.who.facebook_connect.missing_optional'
REPOZE_WHO_LOGGER = 'repoze.who.logger'


class FacebookConnectError(Exception):
    pass


FBClientConf = namedtuple('FBClientConf',
                          'app_id '
                          'app_secret '
                          'api_version_tuple '
                          'api_version_string ')


class FacebookApiClientConfig(object):
    _config = None

    def __init__(self, app_id=None, app_secret=None, version=None):
        version_str = self._version_tuple_to_string(version) \
            if version is not None else None

        if app_id is not None \
                and app_secret is not None \
                and version is not None:
            self._config = FBClientConf(app_id, app_secret, version,
                                        version_str)

    @staticmethod
    def _version_tuple_to_string(version):
        return u'.'.join(map(str, version))

    def _get_client_config(self):
        if self._config is None:
            from tg import config

            try:
                api_version = tuple(config.get('pyfacebook.api_version',
                                               None).split('.'))
            except AttributeError:
                raise FacebookConnectError('You must supply a '
                                           '"pyfacebook.api_version" '
                                           'configuration parameter, '
                                           'for example "2.3".')

            api_version_str = self._version_tuple_to_string(api_version)

            self._config = FBClientConf(config['pyfacebook.appid'],
                                        config['pyfacebook.secret'],
                                        api_version, api_version_str)

        return self._config

    @property
    def version_tuple(self):
        return self._get_client_config().api_version_tuple

    @property
    def version_string(self):
        return self._get_client_config().api_version_string

    @property
    def app_id(self):
        return self._get_client_config().app_id

    @property
    def app_secret(self):
        return self._get_client_config().app_secret


client_config = FacebookApiClientConfig()


class Response(WebObResponse):
    """WebOb Response subclass
    """
    content = WebObResponse.body

    def wsgi_response(self):
        return self.status, self.headers, self.body

    def signed_cookie(self, name, data, secret=None, **kwargs):
        """Save a signed cookie with ``secret`` signature

        Saves a signed cookie of the pickled data. All other keyword
        arguments that ``WebOb.set_cookie`` accepts are usable and
        passed to the WebOb set_cookie method after creating the signed
        cookie value.

        This implementation fixes the problem when base64.encodestring,
         originally used, returned an endline-partitioned string.
        """
        pickled = pickle.dumps(data, pickle.HIGHEST_PROTOCOL)
        sig = hmac.new(secret.encode('ascii'), pickled,
                       sha1).hexdigest().encode('ascii')
        self.set_cookie(name, sig + base64.b64encode(pickled), **kwargs)


class FacebookConnectIdentificationPlugin(object):
    """The repoze.who FacebookConnect plugin

    This class contains 2 plugin types and is thus implementing
    IIdentifier and IAuthenticator.
    (check the `repoze.who documentation <http://static.repoze.org/bfgdocs/>`_
    for what all these plugin types do.)

    A (potential) Facebook user visiting this site, can be in one of
    the following three states
    (http://wiki.developers.facebook.com/index.php/Detecting_Connect_Status):

       1.  Connected - the user is logged in to Facebook and has
           already connected with your website.  You must be in this
           state to make API calls on the user's behalf. This state is
           returned as FB.ConnectState.connected if you call
           FB.Connect.get_status.

       2.  Not logged in - this state means that the user is not
           logged in to Facebook. Because the user is not logged in to
           Facebook, we don't know whether the user has connected with
           your website. In order to make API calls on the user's
           behalf, you must first have the user log in (and
           potentially connect) with your site. This state is returned
           as ConnectState.userNotLoggedIn if you call
           FB.Connect.get_status.

       3.  Not authorized - this state means that the user is logged
           in to Facebook but has not yet connected with your
           website. In order to make API calls on the user's behalf,
           you must first have the user connect with your site. This
           state is returned as ConnectState.appNotAuthorized if you
           call FB.Connect.get_status.

    """
    implements(IIdentifier, IAuthenticator)

    _has_already_logged_fb_version = False

    def __init__(self,
                 fb_connect_field='fb_connect',
                 error_field='',
                 db_session=None,
                 user_class=None,
                 fb_user_class=None,
                 session_name='',
                 login_handler_paths=None,
                 logout_handler_paths=None,
                 login_form_url='',
                 logged_in_url='',
                 logged_out_url='',
                 came_from_field='',
                 rememberer_name='',
                 identified_hook=None,
                 mandatory_permissions=None,
                 optional_permissions=None,
                 fields=None,
                 v1_perms=None,
                 ):

        self.rememberer_name = rememberer_name
        self.login_handler_paths = (login_handler_paths
                                    if login_handler_paths else [])
        self.logout_handler_paths = (logout_handler_paths
                                     if logout_handler_paths else [])
        self.login_form_url = login_form_url
        self.v1_perms = v1_perms

        self.user_class = user_class
        self.fb_user_class = fb_user_class
        self.db_session = db_session

        self.session_name = session_name
        self.error_field = error_field
        self.came_from_field = came_from_field
        self.logged_out_url = logged_out_url
        self.logged_in_url = logged_in_url

        self.identified_hook = identified_hook

        self.mandatory_permissions = set(mandatory_permissions if
                                         mandatory_permissions else [
            'installed'])
        self.optional_permissions = set(optional_permissions
                                        if optional_permissions else [])

        self.fields = fields if fields is not None else [
            u'birthday_date',
            u'first_name',
            u'last_name',
            u'locale',
            u'name',
            u'sex',
        ]

        self.fb_connect_field = fb_connect_field

    def _get_rememberer(self, environ):
        return environ['repoze.who.plugins'][self.rememberer_name]

    @staticmethod
    def _set_handler(environ, response):
        environ['repoze.who.application'] = response

    @classmethod
    def _redirect(cls, environ, target_url=None, response=None):
        """Redirect to target_url.
        """
        if response is None:
            response = Response()

        response.status = FOUND
        response.location = target_url

        cls._set_handler(environ, response)

        environ[REPOZE_WHO_LOGGER] \
            .debug('Redirecting to {0!r}'.format(target_url))

    @staticmethod
    def _log_graph_api_exception(message, exception, environ):
        environ[REPOZE_WHO_LOGGER] \
            .warn('%s %s: type=%r, message=%r', message, type(exception),
                  exception.type, exception.message)

    # IIdentifier
    def _redirect_to_perms_dialog(self, environ, redirect_to_self_url,
                                  perms=None):
        if perms is None:
            perms = self.v1_perms
        target_url = auth_url(client_config.app_id,
                              redirect_to_self_url,
                              perms=perms)
        self._redirect(environ, target_url=target_url)

    def _logout_json(self, environ, response):
        environ[REPOZE_WHO_LOGGER].info('_logout_json')

        # Set forget headers.
        for a, v in self.forget(environ, {}):
            environ[REPOZE_WHO_LOGGER] \
                .debug('forgetting a={0!r}, v={1!r}'.format(a, v))
            response.headers.add(a, v)

        self._set_handler(environ, response)

        return {}  # Unset authentication information.

    def _logout_and_redirect(self, environ, response):
        self._redirect(environ, target_url=self.logged_out_url,
                       response=response)

        # Set forget headers.
        for a, v in self.forget(environ, {}):
            response.headers.add(a, v)

        return {}  # Unset authentication information.

    def _logout(self, environ, request, response):
        if request.path.endswith('.json'):
            self._logout_json(environ, response)
        else:
            self._logout_and_redirect(environ, response)

    @staticmethod
    def _get_full_login_handler_url(request):
        return request.application_url + request.path

    def _deduct_default_target_url(self, request):
        return request.params.get(self.came_from_field, self.logged_in_url)

    def identify(self, environ):
        """This method is called when a request is incoming.

        If credentials are found, the returned identity mapping will
        contain an arbitrary set of key/value pairs.

        Return None to indicate that the plugin found no appropriate
        credentials.

        An IIdentifier plugin is also permitted to ``pre-authenticate''
        an identity.  If the identifier plugin knows that the identity
        is ``good'' (e.g. in the case of ticket-based authentication
        where the user id is embedded into the ticket), it can insert a
        special key into the identity dictionary: repoze.who.userid.
        If this key is present in the identity dictionary, no
        authenticators will be asked to authenticate the identity.
        """
        if not self._has_already_logged_fb_version:
            environ[REPOZE_WHO_LOGGER].info(u'Using Facebook API v%s',
                                            client_config.version_string)
            self._has_already_logged_fb_version = True

        request = Request(environ)
        response = Response()

        # First test for logout as we then don't need the rest.
        if request.path in self.logout_handler_paths:
            return self._logout(environ, request, response)  # --> None

        # Then we check that we are actually on the URL which is
        # supposed to be the url to return to (login_handler_path in
        # configuration) this URL is used for both: the answer for the
        # login form and when the openid provider redirects the user
        # back.
        elif request.path not in self.login_handler_paths:
            return None

        try:
            request.scheme = request.headers['X-Forwarded-Proto']
        except KeyError:
            pass

        login_handler_url = self._get_full_login_handler_url(request)
        environ[REPOZE_WHO_LOGGER].debug(u'login_handler_url: %r',
                                         login_handler_url)
        default_target_url = self._deduct_default_target_url(request)

        if 'access_token' in request.params and 'uid' in request.params:
            fb_user = {
                'access_token': request.params['access_token'],
                'uid': request.params['uid'],
            }

            data_source = 'from params'

        elif 'code' in request.params:
            try:
                fb_user = GraphAPI(version=client_config.version_string) \
                    .get_access_token_from_code(request.params['code'],
                                                login_handler_url,
                                                client_config.app_id,
                                                client_config.app_secret)
            except GraphAPIError as e:
                self._log_graph_api_exception(
                    'Exception in get_access_token_from_code()', e, environ)
                self._redirect(environ, target_url=default_target_url,
                               response=response)
                return None

            data_source = 'via Facebook "code"'

        else:
            try:
                fb_user = get_user_from_cookie(request.cookies,
                                               client_config.app_id,
                                               client_config.app_secret)
            except GraphAPIError as e:
                self._log_graph_api_exception(
                    'Exception in get_user_from_cookie()', e, environ)
                # Redirect to Facebook to get a code for a new access token.
                self._redirect_to_perms_dialog(environ, login_handler_url)
                return None

            data_source = 'from cookie'

        environ[REPOZE_WHO_LOGGER] \
            .info('Received fb_user = %r (%s)', fb_user, data_source)

        # Store a local instance of the user data so we don't need
        # a round-trip to Facebook on every request

        try:
            graph = GraphAPI(fb_user["access_token"],
                             version=client_config.version_string)
            profile = graph.get_object('me')
            if 'id' not in profile:
                environ[REPOZE_WHO_LOGGER] \
                    .warn('Facebook Python-SDK received no uid.')
                return self._logout(environ, request, response)  # --> None

            if 'uid' in fb_user:
                assert profile['id'] == fb_user['uid']
            else:
                fb_user['uid'] = profile['id']

            permissions = graph.get_object('me/permissions')['data']
            environ[REPOZE_WHO_LOGGER].info(u'Granted Facebook permissions: %r',
                                            permissions)

            if client_config.version_tuple >= (2, 0):
                granted = [
                    item['permission'] for item in permissions
                    if item['status'] == 'granted'
                ]
                missing_mandatory = self.mandatory_permissions - set(granted)
                missing_optional = self.optional_permissions - set(granted)

                if missing_optional:
                    environ[REPOZE_WHO_LOGGER] \
                        .info(u'Missing optional permissions: %r',
                              missing_optional)
                    environ[FACEBOOK_CONNECT_REPOZE_WHO_MISSING_OPTIONAL] = \
                        missing_optional

                if missing_mandatory:
                    environ[REPOZE_WHO_LOGGER] \
                        .info(u'Missing mandatory permissions: %r',
                              missing_mandatory)
                    environ[FACEBOOK_CONNECT_REPOZE_WHO_MISSING_MANDATORY] = \
                        missing_mandatory
                    response.status = BAD_REQUEST
                    self._set_handler(environ, response)
                    return None

            else:
                # Legacy, against FB API < v2.0:
                if 'email' not in permissions:
                    environ[REPOZE_WHO_LOGGER].warn(
                        'No permissions to access email address, '
                        'will redirect to permission dialog.')
                    self._redirect_to_perms_dialog(environ, login_handler_url,
                                                   perms=['email'])
                    return None

        except GraphAPIError as e:
            self._log_graph_api_exception('Exception in get_object()', e,
                                          environ)
            raise

        profile['access_token'] = fb_user['access_token']

        environ[REPOZE_WHO_LOGGER].info('graph.get_object("me") = %r', profile)

        if self.identified_hook is None:  # or (fb_user is None):
            environ[REPOZE_WHO_LOGGER] \
                .warn('identify(): No identified_hook was provided.')
            self._redirect(environ, target_url=default_target_url,
                           response=response)
            return None

        self._set_handler(environ, response)

        identity = {}

        self.identified_hook(profile['id'], profile, environ, identity,
                             response)

        return identity

    # IIdentifier
    def remember(self, environ, identity):
        """Remember the Facebook Connect in the session we have anyway.
        """
        return self._get_rememberer(environ).remember(environ, identity)

    # IIdentifier
    def forget(self, environ, identity):
        """Forget about the authentication again.
        """
        return self._get_rememberer(environ).forget(environ, identity)

    # IAuthenticator
    @staticmethod
    def authenticate(environ, identity):
        """Dummy authenticator

        This takes the Facebook Connect identity found and uses it as
        the userid. Normally you would want to take the
        fb_connect and search a user for it to map maybe
        multiple fb_connects to a user.  This means for you to
        simply implement something similar to this.

        """
        environ[REPOZE_WHO_LOGGER].debug(
            'authenticate: identity = %s', identity)

        if FACEBOOK_CONNECT_REPOZE_WHO_ID_KEY in identity:
            environ[REPOZE_WHO_LOGGER] \
                .info('authenticated: %s ',
                      identity[FACEBOOK_CONNECT_REPOZE_WHO_ID_KEY])

            return identity.get(FACEBOOK_CONNECT_REPOZE_WHO_ID_KEY)

        return None

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, id(self))
