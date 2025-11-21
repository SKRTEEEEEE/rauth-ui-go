# feat(oauth): Task 6: OAuth GitHub. Closes #6

## Resumen de Cambios
- GitHub OAuth ahora firma todas las solicitudes HTTP con un `User-Agent` consistente y reutiliza un cliente HTTP con `timeout` para evitar conexiones colgadas.
- Se ampliaron los tests unitarios, de integración y de endpoints para cubrir cabeceras obligatorias, URLs inválidas y el comportamiento ante tokens sin `refresh_token`.
- Se añadió un helper básico en `utils/azure.go` que inicializa un cliente de Azure Blob Storage desde variables de entorno y provee utilidades para subir y borrar blobs.

## Archivos Destacados
1. `oauth/github.go`
   - Nuevo encabezado `githubUserAgent` y cliente HTTP reutilizable.
   - Los métodos de intercambio y de perfil ahora envían el `User-Agent` requerido por GitHub.
2. `oauth/github_test.go` y `oauth/github_integration_test.go`
   - Casos adicionales para validar cabeceras, errores de URL y flujos sin `refresh_token`.
3. `handlers/auth_github_endpoint_test.go`
   - Se verifican errores por `app_id` inválido en el endpoint de autorización.
4. `utils/azure.go`
   - Implementación mínima de subida y eliminación de blobs usando `azblob`.

## Validaciones Ejecutadas
```
go test ./...
go vet ./...
go build ./...
docker compose up -d --build
curl http://localhost:8080/health
docker compose down
```

## Notas
- `go mod tidy` añadió las dependencias de Azure SDK necesarias para futuros hitos.
- Los tests de integración se ejecutaron con las variables sensibles tomadas de `.env`, y se aislaron temporalmente al correr la suite completa.
