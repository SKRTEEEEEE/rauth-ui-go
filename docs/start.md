# 🚀 Configuración Google OAuth - Milestone 5

## Configurar Google OAuth (Obligatorio para Milestone 5)

- [ ] **1. Ir a Google Cloud Console**  
  👉 https://console.cloud.google.com/

- [ ] **2. Crear proyecto OAuth**  
  - Crea nuevo proyecto o selecciona existente
  - Ve a "APIs & Services" → "Credentials"

- [ ] **3. Configurar pantalla de consentimiento**  
  - "OAuth consent screen" → External
  - Scopes: `email` y `profile`

- [ ] **4. Crear credenciales OAuth 2.0**  
  - "Create Credentials" → "OAuth client ID"
  - Tipo: **Web application**
  - **Redirect URI**: `http://localhost:8080/api/v1/oauth/callback/google`

- [ ] **5. Copiar credenciales a `.env`**  
  ```env
  GOOGLE_CLIENT_ID=tu-client-id.apps.googleusercontent.com
  GOOGLE_CLIENT_SECRET=GOCSPX-tu-secret
  ```

- [ ] **6. Reiniciar app**  
  ```bash
  docker-compose restart app
  ```

---

**Listo!** Ahora puedes probar el flujo OAuth completo con Google.
