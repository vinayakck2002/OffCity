from rest_framework.permissions import BasePermission

class IsShopOwner(BasePermission):
    """
    Custom permission to allow access only to users who are shop owners.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and getattr(request.user, 'is_shop_owner', False))