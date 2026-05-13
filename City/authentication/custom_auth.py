from rest_framework_simplejwt.authentication import JWTAuthentication

class CookieJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # Aadyam header-il nokkum (Normal vazhi)
        header = self.get_header(request)
        
        if header is None:
            # Header-il illenkil, nammude Cookie-yil ninnu token edukkum!
            raw_token = request.COOKIES.get('access_token') or None
        else:
            raw_token = self.get_raw_token(header)

        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        return self.get_user(validated_token), validated_token