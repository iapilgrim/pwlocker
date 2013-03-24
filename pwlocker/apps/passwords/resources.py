from djangorestframework.resources import ModelResource
from djangorestframework.serializer import Serializer
from django.core.urlresolvers import reverse

from apps.users.resources import UserResource
from models import Password, PasswordContact


class PasswordContactResource(ModelResource):
    model = PasswordContact
    ordering = ('to_user__first_name',)
    fields = ('id', 'url', ('to_user', 'UserResource'), ('from_user', 'UserResource'))
    ignore_fields = ('id',)

    def validate_request(self, data, files=None):
        """
        Backbone.js will submit all fields in the model back to us, but
        some fields are set as uneditable in our Django model. So we need
        to remove those extra fields before performing validation.
        """
        for key in self.ignore_fields:
            if key in data:
                del data[key]

        return super(PasswordContactResource, self).validate_request(data, files)


class CurrentUserSingleton(object):
    """
    Literally the only way I can find to give the PasswordResource access
    to the current user object.
    """
    user = None

    @classmethod
    def set_user(cls, user):
        cls.user = user


class PasswordResource(ModelResource):
    model = Password
    # by default, django rest framework won't return the ID - backbone.js
    # needs it though, so don't exclude it
    exclude = ('created_by',)
    ordering = ('-title',)
    # django rest framework will overwrite our 'url' attribute with its own
    # that points to the resource, so we need to provide an alternative.
    include = ('resource_url',)
    ignore_fields = ('created_at', 'updated_at', 'id', 'maskedPassword',
        'resource_url', 'is_owner')
    fields = ('id', 'title', 'username', 'password', 'url', 'notes',
        'resource_url', 'shares', 'is_owner')

    related_serializer = PasswordContactResource

    def is_owner(self, instance):
        """
        Returns True if this resource was created by the current user.
        """
        return instance.created_by == obj.request.user.pk

    def url(self, instance):
        """
        Return the instance URL. If we don't specify this, django rest
        framework will return a generated URL to the resource
        """
        return instance.url

    def resource_url(self, instance):
        """
        An alternative to the 'url' attribute django rest framework will
        add to the model.
        """
        return reverse('passwords_api_instance',
                       kwargs={'id': instance.id})

    def validate_request(self, data, files=None):
        """
        Backbone.js will submit all fields in the model back to us, but
        some fields are set as uneditable in our Django model. So we need
        to remove those extra fields before performing validation.
        """
        for key in self.ignore_fields:
            if key in data:
                del data[key]

        return super(PasswordResource, self).validate_request(data, files)
