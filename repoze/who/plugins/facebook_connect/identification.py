# -*- coding: utf-8 -*-

import base64
import hmac

from pylons.controllers.util import Response as PylonsResponse
from repoze.who.interfaces import IIdentifier, IAuthenticator
from webob import Request
from zope.interface import implements
from tg import config

try:
    import cPickle as pickle
except ImportError:
    import pickle
try:
    from hashlib import sha1
except ImportError:
    import sha as sha1

import facebook


FACEBOOK_CONNECT_REPOZE_WHO_ID_KEY = 'repoze.who.facebook_connect.userid'
REPOZE_WHO_LOGGER = 'repoze.who.logger'

class Response(PylonsResponse):
    def signed_cookie(self, name, data, secret=None, **kwargs):
        """Save a signed cookie with ``secret`` signature
        
        Saves a signed cookie of the pickled data. All other keyword
        arguments that ``WebOb.set_cookie`` accepts are usable and
        passed to the WebOb set_cookie method after creating the signed
        cookie value.

        This implementation fixes the problem when
        base64.encodestring, originally used, returned an
        endline-partitioned string.
        """
        pickled = pickle.dumps(data, pickle.HIGHEST_PROTOCOL)
        sig = hmac.new(secret, pickled, sha1).hexdigest()
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

    def __init__(self,
                 fb_connect_field='fb_connect', 
                 error_field='',
                 db_session=None,
                 user_class=None,
                 fb_user_class=None,
                 session_name='',
                 login_handler_path='',
                 logout_handler_path='',
                 login_form_url='',
                 logged_in_url='',
                 logged_out_url='',
                 came_from_field='',
                 rememberer_name='',
                 identified_hook=None,
                 fields=None,
                 scope=None,
                 ):
        
        self.rememberer_name = rememberer_name
        self.login_handler_path = login_handler_path
        self.logout_handler_path = logout_handler_path
        self.login_form_url = login_form_url
        self.scope = scope

        self.user_class = user_class
        self.fb_user_class = fb_user_class
        self.db_session = db_session
        
        self.session_name = session_name
        self.error_field = error_field
        self.came_from_field = came_from_field
        self.logged_out_url = logged_out_url
        self.logged_in_url = logged_in_url
        
        self.identified_hook = identified_hook

        self.fields = fields or [
            #u'affiliations',
            #u'birthday',
            u'birthday_date',
            #u'current_location',
            u'first_name',
            u'last_name',
            u'locale',
            u'name',
            u'sex',
            #u'status',
            ]

        self.fb_connect_field = fb_connect_field
            
    def _get_rememberer(self, environ):
        rememberer = environ['repoze.who.plugins'][self.rememberer_name]
        return rememberer
    
    def _redirect_to(self, environ, target_url=None, cookies=[], response=None):
        """Redirect to target_url if given, or to came_from if
        defined.  Otherwise, redirect to standard logged_in_url page.
        """
        if target_url is None:
            target_url = Request(environ).params.get(self.came_from_field, '') \
                         or self.logged_in_url

        if response is None:
            response = Response()
        
        # Redirect.
        response.status = 302           # HTTP Status: Found.
        response.location = target_url

        # Add cookie headers, if requested.
        for (cookie_identity, cookie_data, cookie_parameters) in cookies:
            response.signed_cookie(cookie_identity, cookie_data,
                                   **cookie_parameters)
            
        environ['repoze.who.application'] = response    

    # def _fb_factory(self):
    #     return facebook.Facebook(config['pyfacebook.apikey'],
    #                              config['pyfacebook.secret'])

    # IIdentifier
    def identify(self, environ):
        """This method is called when a request is incoming.
        
        If credentials are found, the returned identity mapping will
        contain an arbitrary set of key/value pairs.
        
        Return None to indicate that the plugin found no appropriate
        credentials.

        An IIdentifier plugin is also permitted to ``preauthenticate''
        an identity.  If the identifier plugin knows that the identity
        is ``good'' (e.g. in the case of ticket-based authentication
        where the userid is embedded into the ticket), it can insert a
        special key into the identity dictionary: repoze.who.userid.
        If this key is present in the identity dictionary, no
        authenticators will be asked to authenticate the identity.
        """
        request = Request(environ)

        # First test for logout as we then don't need the rest.
        if request.path == self.logout_handler_path:
            self._logout_and_redirect(environ)
            return None                 # No identity was found.
        
        # Then we check that we are actually on the URL which is
        # supposed to be the url to return to (login_handler_path in
        # configuration) this URL is used for both: the answer for the
        # login form and when the openid provider redirects the user
        # back.
        elif request.path != self.login_handler_path:
            return None
        
        # environ[REPOZE_WHO_LOGGER].debug('request.environ = %s', pformat(request.environ))
        
        #fb = self._fb_factory()
        redirect_to_self_url = request.application_url + self.login_handler_path
        if 'access_token' in request.params and 'uid' in request.params:
            fb_user = {
                'access_token': request.params['access_token'],
                }
        elif 'code' in request.params:
            try:
                fb_user = facebook.get_access_token_from_code(
                    request.params['code'],
                    redirect_to_self_url,
                    config['pyfacebook.appid'],
                    config['pyfacebook.secret'])
            except facebook.GraphAPIError as e:
                environ[REPOZE_WHO_LOGGER] \
                   .warn(
                        'Exception in get_access_token_from_code() %s: '
                        'type=%s, '
                        'message=%s',
                    type(e), repr(e.type), repr(e.message))
                self._logout_and_redirect(environ)
                return None
        else:
            try:
                fb_user = facebook.get_user_from_cookie(request.cookies,
                                                        config['pyfacebook.appid'],
                                                        config['pyfacebook.secret'])
            except facebook.GraphAPIError as e:
                environ[REPOZE_WHO_LOGGER] \
                    .warn('Exception in get_user_from_cookie() %s: type=%s, message=%s',
                          type(e), repr(e.type), repr(e.message))
                # Redirect to Facebook to get a code for a new access token.
                target_url = "https://www.facebook.com/dialog/oauth?"\
                             "client_id={client_id}" \
                             "&redirect_uri={uri}" \
                             .format(client_id=config['pyfacebook.appid'],
                                     uri=redirect_to_self_url)
                if self.scope:
                    target_url += ("&scope=" + self.scope)
                self._redirect_to(environ, target_url=target_url)
                return None

        environ[REPOZE_WHO_LOGGER] \
            .info('Received (from cookie) fb_user = %s', fb_user)
        # Store a local instance of the user data so we don't need
        # a round-trip to Facebook on every request
        
        try:
            graph = facebook.GraphAPI(fb_user["access_token"])
            profile = graph.get_object("me")

            if not 'id' in profile:
                environ[REPOZE_WHO_LOGGER] \
                    .warn('Facebook Python-SDK received no uid.')
                self._logout_and_redirect(environ)
                return None
            if 'uid' in fb_user:
                assert profile['id'] == fb_user['uid']
            else:
                fb_user['uid'] = profile['id']
            
        except facebook.GraphAPIError as e:
            environ[REPOZE_WHO_LOGGER] \
                .warn('Received %s: type=%s, message=%s',
                          type(e), repr(e.type), repr(e.message))
            
            # Error 102: Session key invalid or no longer valid.
            # if e.code == 102:
            #     # E.g., delete the cookie and send the user to
            #     # Facebook to login.
            #     environ[REPOZE_WHO_LOGGER].warn('Facebook Error: ' \
            #                   'Session key invalid or no longer valid.')
            #     environ[REPOZE_WHO_LOGGER].warn('Logging out from Facebook session.')
            #     response = Response(request=request)
            #     fb.logout(response)
            #     environ['repoze.who.application'] = response
            #     return None
            raise
        
        profile['access_token'] = fb_user['access_token']
        
        environ[REPOZE_WHO_LOGGER] \
            .warn('graph.get_object("me") = %s', repr(profile))
        
        if self.identified_hook is None:  # or (fb_user is None):
            environ[REPOZE_WHO_LOGGER] \
                .warn('identify(): No identified_hook was provided.')
            self._redirect_to(environ, None)
            return None

        identity = dict()
        
        authenticated, redirect_to_url, cookies \
            = self.identified_hook(profile['id'], profile, environ, identity)
        
        self._redirect_to(environ, redirect_to_url, cookies)
        
        return identity
    
    def _logout_and_redirect(self, environ):
        response = Response()

        # Set forget headers.
        for a, v in self.forget(environ, {}):
            response.headers.add(a, v)
            
        response.status = 302
        response.location = self.logged_out_url
        environ['repoze.who.application'] = response
        
        return {}                  # Unset authentication information.
    
    # IIdentifier
    def remember(self, environ, identity):
        """Remember the Facebook Connect in the session we have
        anyway.
        """
        rememberer = self._get_rememberer(environ)
        r = rememberer.remember(environ, identity)
        return r

    # IIdentifier
    def forget(self, environ, identity):
        """Forget about the authentication again.
        """
        rememberer = self._get_rememberer(environ)
        return rememberer.forget(environ, identity)

    # IAuthenticator
    def authenticate(self, environ, identity):
        """Dummy authenticator
        
        This takes the Facebook Connect identity found and uses it as
        the userid. Normally you would want to take the
        fb_connect and search a user for it to map maybe
        multiple fb_connects to a user.  This means for you to
        simply implement something similar to this.
        
        """
        environ[REPOZE_WHO_LOGGER].debug('authenticate: identity = %s', identity)

        if FACEBOOK_CONNECT_REPOZE_WHO_ID_KEY in identity:
            environ[REPOZE_WHO_LOGGER].info('authenticated : %s ',
                          identity[FACEBOOK_CONNECT_REPOZE_WHO_ID_KEY])

            return identity.get(FACEBOOK_CONNECT_REPOZE_WHO_ID_KEY)

        return None

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, id(self))
