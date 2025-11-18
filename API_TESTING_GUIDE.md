# Guía de Testing del API - AuthFlow

## 🎯 Propósito

Este archivo explica cómo usar `api-workflow.http` para probar el flujo completo de AuthFlow desde la perspectiva del usuario final y del desarrollador que integra el SDK.

## 📋 Prerrequisitos

### 1. Servidor corriendo
```bash
docker-compose up -d
```

Verificar que está funcionando:
```bash
curl http://localhost:8080/health
```

### 2. Extensión REST Client para VSCode

**Opción A - VSCode REST Client (Recomendado)**
- Instalar extensión: [REST Client](https://marketplace.visualstudio.com/items?itemName=humao.rest-client)
- Abrir `api-workflow.http` en VSCode
- Hacer clic en "Send Request" sobre cada bloque

**Opción B - IntelliJ HTTP Client**
- Disponible en IntelliJ IDEA, WebStorm, etc.
- Abrir `api-workflow.http`
- Hacer clic en el ícono ▶️ junto a cada request

**Opción C - Postman (Manual)**
- Importar los requests manualmente desde el archivo .http
- O usar curl directamente desde terminal

## 🚀 Cómo Usar

### Paso 1: Abrir el archivo
```bash
# En VSCode
code api-workflow.http
```

### Paso 2: Ejecutar requests en orden

El archivo está dividido en **FASES** numeradas. Debes seguirlas en orden:

1. **FASE 1**: Setup del Admin (crear aplicación)
2. **FASE 2**: Configurar proveedores OAuth
3. **FASE 3**: Flujo de autenticación (parcialmente implementado)
4. **FASE 4**: Gestión de sesiones (pendiente Milestone 5)
5. **FASE 5**: Gestión de usuarios (pendiente Milestone 7)
6. **FASE 6**: Monitoreo de usuarios

### Paso 3: Copiar valores importantes

Cuando ejecutes ciertos requests, necesitarás copiar valores para usar en requests posteriores:

```http
### 1.2 - Crear Nueva Aplicación
POST http://localhost:8080/api/v1/admin/apps
X-API-Key: test-api-key-12345
Content-Type: application/json

{
  "name": "Mi App"
}

# 👆 De la respuesta, copiar:
# - "id": "02c520c6-e546-4ea7-8ceb-c249ddef41ce"  ← APP_ID
# - "api_key": "abc123..."                        ← APP_API_KEY
```

Luego reemplazar en los siguientes requests:
```http
GET http://localhost:8080/api/v1/admin/apps/{APP_ID}/oauth
#                                            ↑ Reemplazar aquí
```

## 📖 Estructura del Archivo

### Bloques separados por `###`

Cada request está separado por tres almohadillas:

```http
### 1.1 - Health Check
GET http://localhost:8080/health

###

### 1.2 - Crear Aplicación
POST http://localhost:8080/api/v1/admin/apps
```

Haz clic en "Send Request" que aparece sobre cada línea `GET`, `POST`, `PATCH`, etc.

### Comentarios explicativos

Los comentarios (líneas con `#`) explican:
- Qué hace cada request
- Qué valores copiar
- Qué respuesta esperar
- Cuándo usar cada endpoint

```http
### 2.2 - Habilitar Google OAuth
# Permitir que los usuarios se logueen con Google
PATCH http://localhost:8080/api/v1/admin/apps/{app_id}/oauth/google
X-API-Key: test-api-key-12345
Content-Type: application/json

{
  "enabled": true
}
```

## 🔄 Flujo Completo de Ejemplo

### Escenario: Configurar una nueva aplicación con Google OAuth

```http
# 1. Verificar salud del servidor
### 1.1
GET http://localhost:8080/health
```

```http
# 2. Crear aplicación
### 1.2
POST http://localhost:8080/api/v1/admin/apps
X-API-Key: test-api-key-12345
Content-Type: application/json

{
  "name": "Mi App de Prueba",
  "allowed_redirect_uris": ["http://localhost:3000/callback"],
  "cors_origins": ["http://localhost:3000"]
}

# Respuesta:
# {
#   "id": "02c520c6-e546-4ea7-8ceb-c249ddef41ce",  ← Copiar esto
#   "api_key": "abc123...",
#   ...
# }
```

```http
# 3. Ver proveedores disponibles
### 2.1
GET http://localhost:8080/api/v1/admin/apps/02c520c6-e546-4ea7-8ceb-c249ddef41ce/oauth
#                                            ↑ Pegar el ID aquí
X-API-Key: test-api-key-12345

# Respuesta:
# [
#   { "provider": "google", "enabled": false },
#   { "provider": "github", "enabled": false },
#   ...
# ]
```

```http
# 4. Habilitar Google OAuth
### 2.2
PATCH http://localhost:8080/api/v1/admin/apps/02c520c6-e546-4ea7-8ceb-c249ddef41ce/oauth/google
X-API-Key: test-api-key-12345
Content-Type: application/json

{
  "enabled": true
}

# Respuesta:
# {
#   "provider": "google",
#   "enabled": true,  ← Ahora está habilitado
#   ...
# }
```

```http
# 5. Verificar que se habilitó
### 2.6
GET http://localhost:8080/api/v1/admin/apps/02c520c6-e546-4ea7-8ceb-c249ddef41ce/oauth
X-API-Key: test-api-key-12345

# Respuesta:
# [
#   { "provider": "google", "enabled": true },   ← ✅ Habilitado
#   { "provider": "github", "enabled": false },
#   ...
# ]
```

## 🧪 Testing de Casos de Error

Al final del archivo hay una sección de casos de error:

```http
###############################################################################
# CASOS DE ERROR - Testing de Validaciones
###############################################################################

### ERROR 1 - Proveedor Inválido
PATCH http://localhost:8080/api/v1/admin/apps/{app_id}/oauth/twitter
# 👆 "twitter" no es válido

# Respuesta esperada: 400 Bad Request
# {
#   "error": "Invalid provider. Valid providers: google, github, facebook, microsoft"
# }
```

Estos requests **deben fallar** para demostrar que las validaciones funcionan correctamente.

## 📝 Variables de Entorno (Opcional)

Si quieres evitar copiar/pegar manualmente, puedes usar variables de entorno en VSCode REST Client:

### Crear archivo `.vscode/settings.json`:

```json
{
  "rest-client.environmentVariables": {
    "local": {
      "baseUrl": "http://localhost:8080",
      "apiKey": "test-api-key-12345",
      "appId": "02c520c6-e546-4ea7-8ceb-c249ddef41ce"
    }
  }
}
```

### Usar en requests:

```http
GET {{baseUrl}}/api/v1/admin/apps/{{appId}}/oauth
X-API-Key: {{apiKey}}
```

## 🎓 Entender el Flujo OAuth

### ¿Por qué algunos requests no funcionan en REST Client?

Los requests de **FASE 3** (OAuth flow) no se pueden ejecutar completamente desde REST Client porque:

1. **Request 3.1** hace un redirect 302 a Google
2. Usuario autoriza en Google (fuera de nuestro control)
3. Google redirige a **Request 3.2** con un código temporal
4. El código expira en segundos

**Solución**: Copiar la URL del request 3.1 y pegarla en un navegador:

```
http://localhost:8080/api/v1/oauth/authorize?provider=google&app_id=02c520c6-e546-4ea7-8ceb-c249ddef41ce&redirect_uri=http://localhost:3000/callback
```

Verás el redirect a Google (si los credenciales OAuth están configurados).

## 🔐 Seguridad

### API Key vs App ID

- **API Key**: Secreto, solo en backend del desarrollador
- **App ID**: Público, se puede usar en frontend/SDK

```http
# ❌ NUNCA en frontend:
X-API-Key: test-api-key-12345

# ✅ OK en frontend:
?app_id=02c520c6-e546-4ea7-8ceb-c249ddef41ce
```

### Tokens JWT

Cuando Milestone 5 esté implementado, los requests de FASE 4 y 5 usarán JWT:

```http
GET http://localhost:8080/api/v1/users/me
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## 📊 Estado de Implementación

| Fase | Descripción | Estado |
|------|-------------|--------|
| 1 | Setup Admin | ✅ Completo |
| 2 | Config OAuth Providers | ✅ Completo |
| 3 | OAuth Flow | ⏳ Pendiente (M5) |
| 4 | Gestión Sesiones | ⏳ Pendiente (M5) |
| 5 | Gestión Usuarios | ⏳ Pendiente (M7) |
| 6 | Monitoreo Admin | ✅ Completo |

## 🐛 Troubleshooting

### Error: "Connection refused"

El servidor no está corriendo:
```bash
docker-compose up -d
curl http://localhost:8080/health
```

### Error: "Invalid API key"

Estás usando la API key incorrecta. Para testing, usa:
```
X-API-Key: test-api-key-12345
```

### Error: "Application not found"

El `app_id` en la URL no existe. Verifica que copiaste el ID correcto del response de crear aplicación.

### Error: "Cannot GET /api/v1/..."

La ruta no existe (aún). Verifica en qué Milestone se implementa:
- `/oauth/authorize` → Milestone 5
- `/users/me` → Milestone 7
- etc.

## 💡 Tips

1. **Mantén los responses abiertos**: Copia valores que necesitarás después
2. **Usa nombres descriptivos**: Al crear apps, usa nombres como "Test App 1" para identificarlas
3. **Ejecuta en orden**: Las fases dependen de las anteriores
4. **Lee los comentarios**: Explican qué esperar de cada request
5. **Prueba casos de error**: Asegúrate que las validaciones funcionan

## 📚 Recursos Adicionales

- [REST Client VSCode Docs](https://marketplace.visualstudio.com/items?itemName=humao.rest-client)
- [HTTP Request Syntax](https://www.jetbrains.com/help/idea/http-client-in-product-code-editor.html)
- Documentación del proyecto: `AGENTS.md`
- Task actual: `docs/task/staged/`

## 🎯 Siguiente Paso

Una vez que completes las fases 1 y 2, el proyecto estará listo para:

1. **Milestone 5**: Implementar JWT y OAuth callbacks
2. Entonces podrás probar el flujo completo de login
3. Y finalmente las fases 4 y 5 (sesiones y usuarios)

---

**Happy Testing! 🚀**

*Si encuentras algún problema, revisa los logs del servidor:*
```bash
docker logs rauth-app --tail 50 -f
```
