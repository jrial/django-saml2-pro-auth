from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import (HttpResponse, HttpResponseRedirect,
                         HttpResponseServerError)

from onelogin.saml2.auth import OneLogin_Saml2_Auth

from six import iteritems

from .utils import SAMLError, SAMLSettingsError, prepare_django_request

import distutils


def get_provider_index(request):
    """Helper to get the saml config index of a provider in order to grab
    the proper user map"""
    req = prepare_django_request(request)
    try:
        providers = settings.SAML_PROVIDERS
    except AttributeError:
        raise SAMLSettingsError('SAML_PROVIDERS is not defined in settings')
    try:
        provider = req['get_data']['provider']
    except KeyError:
        provider = list(providers[0].keys())[0]
        req['get_data']['provider'] = provider

    for index, provider_obj in enumerate(providers):
        if list(provider_obj.keys())[0] == provider:
            return provider, index

    raise SAMLError("The provider: %s was not found in settings.py" % provider)


def get_clean_map(user_map, saml_data):
    final_map = dict()
    strict_mapping = getattr(settings, "SAML_USERS_STRICT_MAPPING", True)

    for usr_k, usr_v in iteritems(user_map):
        if strict_mapping:
            if type(usr_v) is dict:
                if 'default' in usr_v.keys():
                    raise SAMLSettingsError('A default value is set for key %s in SAML_USER_MAP while SAML_USERS_STRICT_MAPPING is activated' % usr_k)
                if 'index' in usr_v.keys():
                    final_map[usr_k] = saml_data[usr_v['key']][usr_v['index']]
                else:
                    final_map[usr_k] = saml_data[usr_v['key']]
            else:
                final_map[usr_k] = saml_data[user_map[usr_k]]
        else:
            if type(usr_v) is dict:
                if 'index' in usr_v:
                    final_map[usr_k] = saml_data[usr_v['key']][usr_v['index']] if usr_v['key'] in saml_data else usr_v['default'] if 'default' in usr_v.keys() else None
                else:
                    final_map[usr_k] = saml_data[usr_v['key']] if usr_v['key'] in saml_data else usr_v['default'] if 'default' in usr_v.keys() else None
            else:
                final_map[usr_k] = saml_data[user_map[usr_k]] if user_map[usr_k] in saml_data else None

    return final_map


def get_split_field_map(field_map):
    """
    Split a field map into a local and foreign map. Local fields are fields on
    the user model; foreign fields are fields on models reachable through the
    user model.
    """
    local_field_map = {
        k: v
        for k, v in field_map.items()
        if '.' not in k
    }
    foreign_field_map = {
        k: v
        for k, v in field_map.items()
        if '.' in k
    }
    return local_field_map, foreign_field_map


def process_attr_chain(user, field_map):
    """
    Given a foreign field map, store all attributes on the proper objects.
    """

    def convert_request_value(obj, field_name, value):
        """
        Cast whatever value we receive from the request, which is always a
        string, into the appropriate type. Only handles booleans for now.
        """
        if obj._meta.get_field(field_name).get_internal_type() == 'BooleanField':
            value = bool(distutils.util.strtobool(value))
        return value

    def store_end_of_chain(obj, chain, value=None):
        """
        Store a value on the object at the end of a dot-joined chain of
        attributes.
        """
        if len(chain) == 1:
            if value is not None:
                value = convert_request_value(obj, chain[0], value)
                setattr(obj, chain[0], value)
                obj.save()
            return getattr(obj, chain[0])
        else:
            intermediate = getattr(obj, chain[0])
            return store_end_of_chain(intermediate, chain[1:], value)

    for k, v in field_map.items():
        chain = k.split('.')
        store_end_of_chain(user, chain, v)


class Backend(object): # pragma: no cover

    def authenticate(self, request):
        if not request.session['samlUserdata']:
            return None

        User = get_user_model()
        provider, provider_index = get_provider_index(request)
        user_map = settings.SAML_USERS_MAP[provider_index][provider]

        final_map = get_clean_map(user_map, request.session['samlUserdata'])

        lookup_attribute = getattr(settings, "SAML_USERS_LOOKUP_ATTRIBUTE", "username")
        sync_attributes = getattr(settings, "SAML_USERS_SYNC_ATTRIBUTES", False)

        lookup_map = {
            lookup_attribute: final_map[lookup_attribute]
        }

        local_field_map, foreign_field_map = get_split_field_map(final_map)

        if sync_attributes:
            user, _ = User.objects.update_or_create(defaults=local_field_map, **lookup_map)
        else:
            user, _ = User.objects.get_or_create(defaults=local_field_map, **lookup_map)

        process_attr_chain(user, foreign_field_map)

        if user.is_active:
            return user

    def get_user(self, user_id):
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
