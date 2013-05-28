from identification import FacebookConnectIdentificationPlugin
from repoze.who.utils import resolveDotted


def make_identification_plugin(
    fb_connect_field="fb_connect",
    db_session=None,
    user_class=None,
    fb_user_class=None,
    session_name=None,
    login_handler_path=None,
    logout_handler_paths=None,
    login_form_url=None,
    error_field='error',
    logged_in_url=None,
    logged_out_url=None,
    came_from_field='came_from',
    rememberer_name=None,
    md_provider_name='facebook_connect_md',
    fields='',
):
    if login_form_url is None:
        raise ValueError("login_form_url needs to be given")
    if rememberer_name is None:
        raise ValueError("rememberer_name needs to be given")
    if login_handler_path is None:
        raise ValueError("login_handler_path needs to be given")
    if logout_handler_paths is None:
        raise ValueError("logout_handler_paths needs to be given")
    if session_name is None:
        raise ValueError("session_name needs to be given")
    if logged_in_url is None:
        raise ValueError("logged_in_url needs to be given")
    if logged_out_url is None:
        raise ValueError("logged_out_url needs to be given")

    fields = [attr.strip(',') for attr in fields.split()] or None

    plugin = FacebookConnectIdentificationPlugin(
        fb_connect_field=fb_connect_field,
        error_field=error_field,
        db_session=resolveDotted(db_session),
        user_class=resolveDotted(user_class),
        fb_user_class=resolveDotted(fb_user_class),
        session_name=session_name,
        login_form_url=login_form_url,
        login_handler_path=login_handler_path,
        logout_handler_paths=logout_handler_paths,
        logged_in_url=logged_in_url,
        logged_out_url=logged_out_url,
        came_from_field=came_from_field,
        rememberer_name=rememberer_name,
        md_provider_name=md_provider_name,
        fields=fields,
    )
    return plugin
