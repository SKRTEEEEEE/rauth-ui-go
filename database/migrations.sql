-- ============================================
-- AuthFlow Database Schema
-- ============================================

-- Limpiar tablas si existen (solo para desarrollo)
DROP TABLE IF EXISTS sessions CASCADE;
DROP TABLE IF EXISTS identities CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS oauth_providers CASCADE;
DROP TABLE IF EXISTS applications CASCADE;

-- Eliminar función si existe
DROP FUNCTION IF EXISTS update_updated_at_column() CASCADE;

-- ============================================
-- 1. APPLICATIONS
-- Clientes que usan el servicio de autenticación
-- ============================================
CREATE TABLE applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    api_key VARCHAR(64) UNIQUE NOT NULL,
    allowed_redirect_uris TEXT[] DEFAULT '{}',
    cors_origins TEXT[] DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Índice para búsqueda por API key
CREATE INDEX idx_applications_api_key ON applications(api_key);

COMMENT ON TABLE applications IS 'Clientes que usan el servicio de autenticación';
COMMENT ON COLUMN applications.api_key IS 'API key para autenticar requests del cliente';
COMMENT ON COLUMN applications.allowed_redirect_uris IS 'URIs permitidas para redirigir después de OAuth';

-- ============================================
-- 2. OAUTH PROVIDERS
-- Configuración de proveedores OAuth por aplicación
-- ============================================
CREATE TABLE oauth_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL CHECK (provider IN ('google', 'github', 'facebook', 'microsoft')),
    enabled BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(app_id, provider)
);

-- Índice para búsqueda por app_id
CREATE INDEX idx_oauth_providers_app_id ON oauth_providers(app_id);

COMMENT ON TABLE oauth_providers IS 'Proveedores OAuth habilitados por aplicación';
COMMENT ON COLUMN oauth_providers.enabled IS 'Si el proveedor está habilitado para esta app';

-- ============================================
-- 3. USERS
-- Usuarios finales de las aplicaciones cliente
-- ============================================
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    email VARCHAR(255),
    name VARCHAR(255),
    avatar_url TEXT,
    email_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(app_id, email)
);

-- Índices para búsqueda
CREATE INDEX idx_users_app_id ON users(app_id);
CREATE INDEX idx_users_email ON users(email);

COMMENT ON TABLE users IS 'Usuarios finales de las aplicaciones';
COMMENT ON COLUMN users.email IS 'Email del usuario (puede ser null si solo usa OAuth)';
COMMENT ON COLUMN users.avatar_url IS 'URL del avatar (Azure Blob Storage)';

-- ============================================
-- 4. IDENTITIES
-- Identidades OAuth vinculadas a usuarios
-- ============================================
CREATE TABLE identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL CHECK (provider IN ('google', 'github', 'facebook', 'microsoft')),
    provider_user_id VARCHAR(255) NOT NULL,
    provider_email VARCHAR(255),
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, provider),
    UNIQUE(provider, provider_user_id)
);

-- Índices para búsqueda rápida
CREATE INDEX idx_identities_user_id ON identities(user_id);
CREATE INDEX idx_identities_provider_user ON identities(provider, provider_user_id);

COMMENT ON TABLE identities IS 'Identidades OAuth de los usuarios';
COMMENT ON COLUMN identities.provider_user_id IS 'ID del usuario en el proveedor (ej: Google user ID)';
COMMENT ON COLUMN identities.access_token IS 'Access token del proveedor (cifrado)';
COMMENT ON COLUMN identities.refresh_token IS 'Refresh token del proveedor (cifrado)';

-- ============================================
-- 5. SESSIONS
-- Sesiones activas de usuarios
-- ============================================
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    last_used_at TIMESTAMP DEFAULT NOW()
);

-- Índices para búsqueda y limpieza
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

COMMENT ON TABLE sessions IS 'Sesiones activas de usuarios';
COMMENT ON COLUMN sessions.token_hash IS 'Hash SHA-256 del JWT para validación';
COMMENT ON COLUMN sessions.expires_at IS 'Fecha de expiración de la sesión';

-- ============================================
-- FUNCIONES AUXILIARES
-- ============================================

-- Función para actualizar updated_at automáticamente
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers para updated_at
CREATE TRIGGER update_applications_updated_at BEFORE UPDATE ON applications
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_oauth_providers_updated_at BEFORE UPDATE ON oauth_providers
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_identities_updated_at BEFORE UPDATE ON identities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- DATOS DE PRUEBA (opcional, para desarrollo)
-- ============================================

-- Aplicación de prueba
INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins) VALUES
    ('Test App', 'test-api-key-12345', 
     ARRAY['http://localhost:3000/auth/callback', 'http://localhost:3000'],
     ARRAY['http://localhost:3000']);

-- Habilitar proveedores OAuth para la app de prueba
INSERT INTO oauth_providers (app_id, provider, enabled)
SELECT id, 'google', true FROM applications WHERE name = 'Test App'
UNION ALL
SELECT id, 'github', true FROM applications WHERE name = 'Test App'
UNION ALL
SELECT id, 'facebook', false FROM applications WHERE name = 'Test App';

-- ============================================
-- VERIFICACIÓN
-- ============================================

-- Ver todas las tablas creadas
SELECT table_name 
FROM information_schema.tables 
WHERE table_schema = 'public' 
ORDER BY table_name;

-- Ver cantidad de registros
SELECT 
    'applications' as table_name, COUNT(*) as count FROM applications
UNION ALL
SELECT 'oauth_providers', COUNT(*) FROM oauth_providers
UNION ALL
SELECT 'users', COUNT(*) FROM users
UNION ALL
SELECT 'identities', COUNT(*) FROM identities
UNION ALL
SELECT 'sessions', COUNT(*) FROM sessions;
