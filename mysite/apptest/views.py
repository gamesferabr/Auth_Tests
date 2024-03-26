from ninja.router import Router
from .models import CustomUser
from django.db import transaction
from .schemas import UserCreateSchema, AuthSchema
from django.contrib.auth import authenticate
from django.http import HttpRequest, JsonResponse
from django.contrib.auth import login
from datetime import timedelta
from .authtoken import CreateAuthToken
from oauth2_provider.decorators import protected_resource
from oauth2_provider.models import AccessToken, RefreshToken
import json

router = Router()

@router.post("/signup")  # Usar POST para criar recursos é uma prática padrão
def signup(request, payload: UserCreateSchema):
    try:
        with transaction.atomic():
            user = CustomUser(email=payload.email)
            user.set_password(payload.password)
            user.save()

        # Retorna apenas a confirmação de criação do usuário
        return {"id": user.id, "email": user.email}
    
    except Exception as e:
        return {"error": str(e)}, 400
    

@router.post("/login")
def login_user(request: HttpRequest, auth: AuthSchema):
    user = authenticate(email=auth.email, password=auth.password)
    
    if user:
        try:
            login(request, user)  # Realiza o login do usuário no sistema
            
            access_token, refresh_token = CreateAuthToken(user).create_tokens()
            
            # Guarda o access_token e refresh_token na sessão
            # request.session['access_token'] = access_token.token
            # request.session['refresh_token'] = refresh_token.token
            
            # Resposta incluindo o access_token e refresh_token
            return JsonResponse({
                'access_token': access_token.token,
                'token_type': 'Bearer',
                'expires_in': timedelta(days=1).total_seconds(),
                'refresh_token': refresh_token.token,
            })
        
        except Exception as e:
            # Resposta em caso de erro na criação dos tokens
            return JsonResponse({"error": str(e)}, status=400)
        
    else:
        # Resposta em caso de falha na autenticação
        return JsonResponse({"error": "Invalid credentials"}, status=400)
    

@router.post("/logout")
@protected_resource()  # Requer autenticação
def logout(request: HttpRequest):
    # Acessa o token da requisição
    token_string = request.headers.get('Authorization').split(' ')[1]
    
    if token_string:
        try:
            # Instancia a classe CreateAuthToken sem especificar um usuário
            # (não necessário para a operação de logout)
            token_helper = CreateAuthToken(user=None)
            
            # Revoga o access_token
            access_token = AccessToken.objects.get(token=token_string)
            token_helper.revoke_token(access_token)
            
            # Revoga o refresh_token associado, se houver
            refresh_token = RefreshToken.objects.filter(access_token=access_token).first()
            if refresh_token:
                token_helper.revoke_token(refresh_token)
                
            return JsonResponse({"message": "Logout successful"}, status=200)
        
        except AccessToken.DoesNotExist:
            return JsonResponse({"error": "Access token not found"}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({"error": "Invalid token"}, status=400)
    

@router.post("/refresh")
@protected_resource()  # Requer autenticação
def refresh_token(request: HttpRequest):
    # Acessa o token da requisição
    body = json.loads(request.body)
    refresh_token_string = body.get("refresh_token")
    if refresh_token_string:
        try:            
            # Instancia a classe CreateAuthToken especificando um usuário
            # (necessário para a operação de atualização do access_token)
            token_helper = CreateAuthToken(user=request.user)
            
            # Busca o refresh_token
            refresh_token = RefreshToken.objects.get(token=refresh_token_string)
            
            # Atualiza o access_token a partir do refresh_token
            access_token = token_helper.att_access_token_from_refresh_token(refresh_token)
            
            return JsonResponse({
                'access_token': access_token.token,
                'token_type': 'Bearer',
                'expires_in': timedelta(days=1).total_seconds(),
            }, status=200)
        
        except RefreshToken.DoesNotExist:
            return JsonResponse({"error": "Refresh token not found"}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({"error": "Invalid token"}, status=400)
    