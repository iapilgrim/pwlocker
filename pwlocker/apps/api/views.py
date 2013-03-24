from django.db.models import Q
#from djangorestframework.mixins import ModelMixin, InstanceMixin, \
#ReadModelMixin, DeleteModelMixin
from rest_framework.mixins import *

#from djangorestframework.permissions import IsAuthenticated
from rest_framework.permissions import IsAuthenticatedOrReadOnly
#from djangorestframework.response import ErrorResponse
from rest_framework.response import Response
#from djangorestframework import status
from rest_framework import status
#from djangorestframework.views import ListOrCreateModelView, InstanceModelView, ModelView
from rest_framework.views import *
from rest_framework.generics import *
from apps.passwords.models import PasswordContact, Password
#from apps.passwords.resources import PasswordResource, PasswordContactResource, \
#CurrentUserSingleton
from apps.passwords.serializers import *
from apps.users.serializers import *


class RestrictPasswordToUserMixin(ListModelMixin):
    """
    Mixin that restricts users to working with their own data
    """
    pass
#    def get_queryset(self):
#        """
#        Only return objects created by, or shared with, the currently
#        authenticated user.
#        """
#        return self.resource.model.objects.filter(Q(created_by=self.user) |
#            Q(shares__to_user=self.user)).distinct()
#
#    def get_instance_data(self, model, content, **kwargs):
#        """
#        Set the created_by field to the currently authenticated user.
#        """
#        content['created_by'] = self.user
#        return super(RestrictPasswordToUserMixin, self).get_instance_data(model, content, **kwargs)
#
#    def initial(self, request, *args, **kwargs):
#        """
#        Set the currently authenticated user on the resource
#        """
#        CurrentUserSingleton.set_user(request.user)
#        return super(ModelMixin, self).initial(request, *args, **kwargs)
#
#    def final(self, request, response, *args, **kargs):
#        """
#        Clear the current user singleton to make sure it doesn't leak
#        """
#        CurrentUserSingleton.set_user(None)
#        return super(ListModelMixin, self).final(request, response, *args, **kargs)


class PasswordListView(RestrictPasswordToUserMixin, ListCreateAPIView):
    """
    List view for Password objects.
    """
#    resource = PasswordResource
#    permissions = (IsAuthenticated, )
    model = Password
    serializer_class = PasswordSerializer
    permission_classes = (IsAuthenticatedOrReadOnly,)

class PasswordInstanceView(RestrictPasswordToUserMixin, RetrieveUpdateDestroyAPIView):
    """
    View for individual Password instances
    """
#    resource = PasswordResource
#    permissions = (IsAuthenticated, )
    permission_classes = (IsAuthenticatedOrReadOnly,)
    model = Password
    serializer_class = PasswordSerializer
    def put(self, request, pk, format=None):
        password = self.get_object(pk)
        serializer = PasswordSerializer(password, data=request.DATA)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
#    def put(self, request, *args, **kwargs):
#        """
#        Only allow the creating user to modify an instance.
#        """
#        model = self.resource.model
#        query_kwargs = self.get_query_kwargs(request, *args, **kwargs)
#
#        try:
#            self.model_instance = self.get_instance(**query_kwargs)
#
#            if self.model_instance.created_by == self.user:
#                return super(RestrictPasswordToUserMixin, self).put(request, *args, **kwargs)
#        except model.DoesNotExist:
#            pass
#        
##        raise Response(status.HTTP_401_UNAUTHORIZED, None, {})
#        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#    def delete(self, request, *args, **kwargs):
#        """
#        Only the creator should be able to delete an instance.
#        """
#        model = self.resource.model
#        query_kwargs = self.get_query_kwargs(request, *args, **kwargs)
#
#        try:
#            instance = self.get_instance(**query_kwargs)
#        except model.DoesNotExist:
#            raise ErrorResponse(status.HTTP_404_NOT_FOUND, None, {})
#
#        if instance.created_by == self.user:
#            instance.delete()
#        else:
#            raise ErrorResponse(status.HTTP_401_UNAUTHORIZED, None, {})
    def delete(self, request, pk, format=None):
        password = self.get_object(pk)
        password.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class PasswordContactListView(ListCreateAPIView):
    """
    List view for PasswordContact objects.
    """
#    resource = PasswordContactResource
#    permissions = (IsAuthenticated, )
    model = PasswordContact
    serializer_class = PasswordContactSerializer
    permission_classes = (IsAuthenticatedOrReadOnly,)
#    def get_queryset(self):
#        """
#        Only return objects where the from_user is the currently authenticated user.
#        """
#        return self.resource.model.objects.filter(from_user=self.user)
#
#    def get_instance_data(self, model, content, **kwargs):
#        """
#        Set the from_user field to the currently authenticated user.
#        """
#        content['from_user'] = self.user
#        return super(PasswordContactListView, self).get_instance_data(model, content, **kwargs)


class ReadOnlyInstanceModelView(RetrieveModelMixin, CreateModelMixin, SingleObjectAPIView):
    """
    A view which provides default operations for read/delete against a model instance
    but that prevents updates.
    """
    _suffix = 'Instance'


class PasswordContactReadOrDeleteInstanceView(ReadOnlyInstanceModelView):
    """
    View for individual PasswordContact instances
    """
#    resource = PasswordContactResource
#    permissions = (IsAuthenticated, )
    model = PasswordContact
    serializer_class = PasswordContactSerializer

#    def delete(self, request, *args, **kwargs):
#        """
#        Deletes shares from Passwords when a PasswordContact is deleted
#        """
#        model = self.resource.model
#        query_kwargs = self.get_query_kwargs(request, *args, **kwargs)
#
#        try:
#            instance = self.get_instance(**query_kwargs)
#        except model.DoesNotExist:
#            raise ErrorResponse(status.HTTP_404_NOT_FOUND, None, {})
#
#        # remove any shares from any passwords shared with this contact
#        password_contacts = PasswordContact.objects.filter(from_user=self.user,
#            to_user=instance.to_user)
#
#        for password_contact in password_contacts:
#            password_contact.delete()
#
#        instance.delete()
#        return


class UserView(RetrieveModelMixin, CreateModelMixin, SingleObjectAPIView):
    """
    View for individual Users lets users find other users by username
    """
#    resource = UserResource
#    permissions = (IsAuthenticated, )
    model = User
    serializer_class = UserSerializer
    permission_classes = (IsAuthenticatedOrReadOnly,)
    def get_queryset(self):
        """
        Filter the current user from search results to prevent them sharing
        with themselves.
        """
        return self.model.objects.filter(~Q(id=self.user.id))