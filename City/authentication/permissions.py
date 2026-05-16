from rest_framework.permissions import BasePermission

class IsShopOwner(BasePermission):
    """
    Custom permission to allow access only to users who are shop owners.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and getattr(request.user, 'is_shop_owner', False))
    
class IsSuperAdmin(BasePermission):
    """
    Custom permission to allow access only to Super Admins.
    """
    def has_permission(self, request, view):
        # User authenticate aayittundennum, is_superuser True aanennum check cheyyunnu
        return bool(request.user and request.user.is_authenticated and request.user.is_superuser)