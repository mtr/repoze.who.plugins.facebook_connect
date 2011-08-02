# -*- coding: utf-8 -*-

import base64
import hmac

from pylons.controllers.util import Response as PylonsResponse
from repoze.who.interfaces import IChallenger, IIdentifier, IAuthenticator
from webob import Request
from zope.interface import implements
from onlive.lib.util import spacelog
import repoze.tm

from tg import config

import logging

try:
    import cPickle as pickle
except ImportError:
    import pickle
try:
    from hashlib import sha1
except ImportError:
    import sha as sha1

import facebook

#_log = logging.getLogger('auth')

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
    
    This class contains 3 plugin types and is thus implementing
    IIdentifier, IChallenger and IAuthenticator.
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
    implements(IChallenger, IIdentifier, IAuthenticator)

    #log = logging.getLogger('auth')
    log = logging.getLogger('.'.join(__name__.split('.')[:-1]))
    
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
                 md_provider_name='facebook_connect_md',
                 fields=None,
                 ):
        
        self.rememberer_name = rememberer_name
        self.login_handler_path = login_handler_path
        self.logout_handler_path = logout_handler_path
        self.login_form_url = login_form_url
        
        self.user_class = user_class
        self.fb_user_class = fb_user_class
        self.db_session = db_session
        
        self.session_name = session_name
        self.error_field = error_field
        self.came_from_field = came_from_field
        self.logged_out_url = logged_out_url
        self.logged_in_url = logged_in_url
        
        self.md_provider_name = md_provider_name
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
    
    def _get_md_provider(self, environ):
        md_provider = environ['repoze.who.plugins'].get(self.md_provider_name)
        return md_provider

    def get_consumer(self,environ):
        session = environ.get(self.session_name,{})
        return consumer.Consumer(session, self.store)

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

        self.log.debug(('\n' * 10) + 'target_url = %s, came_from_field = %s',
                       target_url, Request(environ).params.get(self.came_from_field, ''))
        
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
        spacelog(self.log, 'repoze.tm.isActive() = %s',
                 repoze.tm.isActive(environ))

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
        
        #self.log.debug('request.environ = %s', pformat(request.environ))
        
        #fb = self._fb_factory()

        if 'access_token' in request.params and 'uid' in request.params:
            fb_user = {
                'access_token': request.params['access_token'],
                'uid': request.params['uid'],
                }
        else:
            fb_user = facebook.get_user_from_cookie(request.cookies,
                                                    config['pyfacebook.appid'],
                                                    config['pyfacebook.secret'])
            
        if not fb_user:
            self.log.warn('Facebook Python-SDK did not return any user data.')
            self._logout_and_redirect(environ)
            # response = Response(request=request)
            # # Will also prepare redirection through response's fields.
            # environ['repoze.who.application'] = response
            return None

        self.log.warn('Received (from cookie) fb_user = %s', fb_user)
        # Store a local instance of the user data so we don't need
        # a round-trip to Facebook on every request
        
        try:
            graph = facebook.GraphAPI(fb_user["access_token"])
            profile = graph.get_object("me")

            if not ('id' in profile and profile['id'] == fb_user['uid']):
                self.log.warn('Facebook Python-SDK received invalid uid.')
                self._logout_and_redirect(environ)
                return None
            
        except facebook.GraphAPIError as e:
            self.log.warn('Received %s: type=%s, message=%s',
                          type(e), repr(e.type), repr(e.message))
            
            # Error 102: Session key invalid or no longer valid.
            # if e.code == 102:
            #     # E.g., delete the cookie and send the user to
            #     # Facebook to login.
            #     self.log.warn('Facebook Error: ' \
            #                   'Session key invalid or no longer valid.')
            #     self.log.warn('Logging out from Facebook session.')
            #     response = Response(request=request)
            #     fb.logout(response)
            #     environ['repoze.who.application'] = response
            #     return None
            raise
        
        profile['access_token'] = fb_user['access_token']
        
        self.log.warn('graph.get_object("me") = %s', repr(profile))
        
        md = self._get_md_provider(environ)
        if md is None: # or (fb_user is None):
            self.log.warn('identify(): No metadata provider was found.')
            self._redirect_to(environ, None)
            return None

        identity = dict()
        
        authenticated, redirect_to_url, cookies \
            = md.authenticate_or_register_user(fb_user['uid'], profile,
                                               environ, identity)
        
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

    # IChallenger
    def challenge(self, environ, status, app_headers, forget_headers):
        """The challenge method is called when the
        ``IChallengeDecider`` in ``classifiers.py`` returns ``True``.
        This is the case for either a ``401`` response from the client
        or if the key ``repoze.whoplugins.fb_connect.fb_connect`` is
        present in the WSGI environment.  The name of this key can be
        adjusted via the ``fb_connect_field`` configuration directive.
        
        The latter is the case when we are coming from the login page
        where the user entered the Facebook Connect to use.
        
        ``401`` can come back in any case and then we simply redirect
        to the login form which is configured in the who configuration
        as ``login_form_url``.
        
        TODO: make the environment key to check also configurable in
        the challenge_decider.

        For the Facebook Connect flow check `the Facebook Connect
        documentation
        http://wiki.developers.facebook.com/index.php/Facebook_Connect`.
        """
        request = Request(environ)
        
        # Check for the field present, if not redirect to login_form
        if not request.params.has_key(self.fb_connect_field):
            # redirect to login_form
            res = Response()
            res.status = 302
            res.location = self.login_form_url + "?%s=%s" \
                           % (self.came_from_field, request.url)
            return res
        
        # Now we have an Facebook Connect from the user in the request 
        fb_connect_url = request.params[self.fb_connect_field]
        self.log.debug('Starting Facebook Connect request for : %s', fb_connect_url)       
        try:
        # we create a new Consumer and start the discovery process for the URL given
        # in the library fb_connect_request is called auth_req btw.
            fb_connect_request = self.get_consumer(environ).begin(fb_connect_url)
        except consumer.DiscoveryFailure, exc:
            # eventually no Facebook Connect server could be found
            environ[self.error_field] = 'Error in discovery: %s' %exc[0]
            self.log.info('Error in discovery: %s ' %exc[0])     
            return self._redirect_to_loginform(environ)
        except KeyError, exc:
            # TODO: when does that happen, why does plone.fb_connect use "pass" here?
            environ[self.error_field] = 'Error in discovery: %s' %exc[0]
            self.log.info('Error in discovery: %s ' %exc[0])
            return self._redirect_to_loginform(environ)
            #return None
        # Not sure this can still happen but we are making sure.
        # should actually been handled by the DiscoveryFailure exception above
        if fb_connect_request is None:
            environ[self.error_field] = 'No Facebook Connect services found for %s' %fb_connect_url
            environ['repoze.who.logger'].info('No Facebook Connect services found for: %s ' %fb_connect_url)
            return self._redirect_to_loginform(environ)
       
        # We have to tell the Facebook Connect provider where to send
        # the user after login so we need to compute this from our
        # path and application URL we simply use the URL we are at
        # right now (which is the form) this will be captured by the
        # repoze.who identification plugin later on it will check if
        # some valid Facebook Connect response is coming back
        # trust_root is the URL (realm) which will be presented to the
        # user in the login process and should be your applications
        # url TODO: make this configurable?  return_to is the actual
        # URL to be used for returning to this app
        return_to = request.path_url # we return to this URL here
        trust_root = request.application_url
        environ['repoze.who.logger'].debug('setting return_to URL to : %s ' %return_to)
        
        # TODO: usually you should check
        # fb_connect_request.shouldSendRedirect() but this might say you
        # have to use a form redirect and I don't get why so we do the
        # same as plone.fb_connect and ignore it.
        
        # Request additional information (optional here, could require
        # fields as well)...
        if self.sreg_optional or self.sreg_required:
            fb_connect_request.addExtension(
                sreg.SRegRequest(
                    required = self.sreg_required,
                    optional = self.sreg_optional,
                    )
                )

        # TODO: we might also want to give the application some way of adding
        # extensions to this message.
        redirect_url = fb_connect_request.redirectURL(trust_root, return_to) 
        # # , immediate=False)
        res = Response()
        res.status = 302
        res.location = redirect_url
        environ['repoze.who.logger'].debug('redirecting to : %s ' %redirect_url)

        # now it's redirecting and might come back via the identify() method
        # from the Facebook Connect provider once the user logged in there.
        return res
        
    def _redirect_to_loginform(self, environ={}):
        """redirect the user to the login form"""
        res = Response()
        res.status = 302
        q=''
        ef = environ.get(self.error_field, None)
        if ef is not None:
                q='?%s=%s' %(self.error_field, ef)
        res.location = self.login_form_url+q
        return res
        
                
    # IAuthenticator
    def authenticate(self, environ, identity):
        """Dummy authenticator
        
        This takes the Facebook Connect identity found and uses it as
        the userid. Normally you would want to take the
        fb_connect and search a user for it to map maybe
        multiple fb_connects to a user.  This means for you to
        simply implement something similar to this.
        
        """
        self.log.debug('authenticate: identity = %s', identity)

        if identity.has_key("repoze.who.plugins.facebook_connect.userid"):
            self.log.info('authenticated : %s ',
                          identity['repoze.who.plugins.facebook_connect.userid'])
            return identity.get('repoze.who.plugins.facebook_connect.userid')

        return None

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, id(self))

