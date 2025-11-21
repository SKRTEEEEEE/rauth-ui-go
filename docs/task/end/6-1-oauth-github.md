# feat(oauth): Task 6: OAuth GitHub. Closes #6

## Resumen de Cambios

Se implementó el proveedor OAuth de GitHub para el sistema de autenticación, siguiendo el patrón establecido por el proveedor de Google existente.

## Archivos Modificados

### Nuevos Archivos

1. **`oauth/github.go`**
   - Implementación completa del proveedor OAuth de GitHub
   - Funciones principales:
     - `BuildGitHubAuthURL()`: Construye la URL de autorización de GitHub
     - `ExchangeGitHubCode()`: Intercambia el código de autorización por tokens
     - `GetGitHubUserInfo()`: Obtiene información del usuario desde la API de GitHub
   - URLs de GitHub OAuth configuradas como variables para facilitar testing

2. **`oauth/github_test.go`**
   - Tests unitarios completos para todas las funciones de GitHub OAuth
   - Cobertura de casos:
     - Construcción correcta de URL de autorización
     - Intercambio exitoso de código por tokens
     - Manejo de errores (código inválido, JSON inválido, token inválido)
     - Obtención correcta de información de usuario
     - Manejo de email nulo
     - Verificación de constantes de URL

3. **`oauth/github_integration_test.go`**
   - Tests de integración para el flujo completo de OAuth
   - Tests de:
     - Flujo completo de OAuth
     - Manejo de errores
     - Solicitudes concurrentes
     - Rate limiting

4. **`handlers/auth_github_endpoint_test.go`**
   - Tests de endpoints específicos para GitHub OAuth
   - Verificación de:
     - Solicitud OAuth válida de GitHub
     - Provider no habilitado para la aplicación
     - Provider no encontrado
     - Construcción correcta de URL
     - Comportamiento específico del proveedor

### Archivos Modificados

1. **`handlers/auth.go`**
   - Agregado caso `ProviderGitHub` en `OAuthAuthorize()`:
     - Llama a `oauth.BuildGitHubAuthURL()` para construir la URL de autorización
   - Agregado caso `ProviderGitHub` en `OAuthCallback()`:
     - Intercambia código con `oauth.ExchangeGitHubCode()`
     - Obtiene información de usuario con `oauth.GetGitHubUserInfo()`

## Detalles Técnicos

### Endpoints Soportados

- **GET /api/v1/oauth/authorize?provider=github&app_id={id}&redirect_uri={uri}**
  - Inicia el flujo OAuth de GitHub
  - Redirige a `https://github.com/login/oauth/authorize`

- **GET /api/v1/oauth/callback/github?code={code}&state={state}**
  - Procesa el callback de GitHub
  - Intercambia código por tokens
  - Crea/actualiza usuario e identidad
  - Genera JWT y redirige al cliente

### Scope de OAuth

- `user:email` - Permite leer la información del perfil y email del usuario

### URLs de GitHub OAuth

- Auth URL: `https://github.com/login/oauth/authorize`
- Token URL: `https://github.com/login/oauth/access_token`
- User Info URL: `https://api.github.com/user`

### Variables de Entorno Requeridas

```env
GITHUB_CLIENT_ID=tu-client-id-de-github
GITHUB_CLIENT_SECRET=tu-client-secret-de-github
```

## Tests Ejecutados

```
=== RUN   TestBuildGitHubAuthURL
--- PASS: TestBuildGitHubAuthURL (0.00s)
=== RUN   TestBuildGitHubAuthURL_MissingClientID
--- PASS: TestBuildGitHubAuthURL_MissingClientID (0.00s)
=== RUN   TestExchangeGitHubCode_Success
--- PASS: TestExchangeGitHubCode_Success (0.01s)
=== RUN   TestExchangeGitHubCode_InvalidCode
--- PASS: TestExchangeGitHubCode_InvalidCode (0.00s)
=== RUN   TestExchangeGitHubCode_InvalidJSON
--- PASS: TestExchangeGitHubCode_InvalidJSON (0.00s)
=== RUN   TestGetGitHubUserInfo_Success
--- PASS: TestGetGitHubUserInfo_Success (0.00s)
=== RUN   TestGetGitHubUserInfo_NullEmail
--- PASS: TestGetGitHubUserInfo_NullEmail (0.00s)
=== RUN   TestGetGitHubUserInfo_InvalidToken
--- PASS: TestGetGitHubUserInfo_InvalidToken (0.00s)
=== RUN   TestGetGitHubUserInfo_InvalidJSON
--- PASS: TestGetGitHubUserInfo_InvalidJSON (0.00s)
=== RUN   TestGetGitHubUserInfo_EmptyAccessToken
--- PASS: TestGetGitHubUserInfo_EmptyAccessToken (0.00s)
=== RUN   TestGitHubOAuth_URLConstants
--- PASS: TestGitHubOAuth_URLConstants (0.00s)
=== RUN   TestGitHubOAuth_ReturnTypes
--- PASS: TestGitHubOAuth_ReturnTypes (0.00s)
=== RUN   TestGetGitHubUserInfo_ReturnsOAuthUserInfo
--- PASS: TestGetGitHubUserInfo_ReturnsOAuthUserInfo (0.00s)

PASS
ok      rauth/oauth     2.439s
```

## Notas Adicionales

- La implementación sigue el mismo patrón que el proveedor de Google existente
- GitHub verifica los emails de los usuarios, por lo que `EmailVerified` se establece en `true`
- El ID de usuario de GitHub es un entero de 64 bits que se convierte a string
- Los tests utilizan mock servers para simular las respuestas de la API de GitHub
- La compilación del proyecto fue exitosa (`go build`)

## Siguiente Tarea

- `6-2-oauth-facebook.md` - Implementar proveedor OAuth de Facebook
