import zope.interface 
from repoze.who.interfaces import IChallengeDecider


def fb_connect_challenge_decider(environ, status, headers):
    # We do the default if it's a 401, probably we show a form then.
    if status.startswith('401 '):
        return True
    elif environ.has_key('repoze.whoplugins.facebook_connect.facebook_connect'):
        # In case IIdentification found an facebook_connect it should
        # be in the environ and we do the challenge.
        return True
    return False
    
zope.interface.directlyProvides(fb_connect_challenge_decider, IChallengeDecider)

