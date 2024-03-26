from django.utils.timezone import now
from datetime import timedelta
from oauth2_provider.models import AccessToken, Application, RefreshToken
import secrets

def generate_token():
    # Gera um token seguro. 32 bytes resultam em um token hexadecimal de 64 caracteres.
    return secrets.token_hex(32)

class CreateAuthToken:
    def __init__(self, user):
        self.user = user
        self.application = Application.objects.get(name="myapp")  # Busca a aplicação uma única vez para ambos os tokens

    def create_access_token(self):
        # Cria e retorna um access_token
        access_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token=generate_token(),
            expires=now() + timedelta(days=1),  # Token expira em 1 dia
            scope="read write",
        )
        return access_token

    def create_refresh_token(self, access_token):
        # Cria e retorna um refresh_token associado ao access_token fornecido
        refresh_token = RefreshToken.objects.create(
            user=self.user,
            application=self.application,
            token=generate_token(),
            access_token=access_token,  # Usa o access_token criado anteriormente
        )
        return refresh_token

    def create_tokens(self):
        # Método utilitário para criar ambos os tokens de uma vez
        access_token = self.create_access_token()
        refresh_token = self.create_refresh_token(access_token)
        return access_token, refresh_token
    
    def revoke_token(self, token):
        # Revoga o token fornecido
        token.expires = now()
        token.save()
        return token
    
    def att_access_token_from_refresh_token(self, refresh_token):
        # Verifica se o refresh token pertence ao usuário
        if refresh_token.user != self.user:
            raise Exception("Refresh token does not belong to the authenticated user.")
        
        # Procede com a criação de um novo access token
        access_token = self.create_access_token()
        refresh_token.access_token = access_token
        refresh_token.save()
        return access_token