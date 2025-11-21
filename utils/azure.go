package utils

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	azblobblob "github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
)

// AzureBlobService encapsula un cliente sencillo para subir archivos a Azure Blob Storage.
type AzureBlobService struct {
	client    *azblob.Client
	container string
	endpoint  string
}

// NewAzureBlobServiceFromEnv crea el cliente usando las variables de entorno esperadas.
func NewAzureBlobServiceFromEnv() (*AzureBlobService, error) {
	accountName := os.Getenv("AZURE_STORAGE_ACCOUNT")
	accountKey := os.Getenv("AZURE_STORAGE_KEY")
	container := os.Getenv("AZURE_STORAGE_CONTAINER")

	if accountName == "" || accountKey == "" || container == "" {
		return nil, fmt.Errorf("missing Azure storage configuration")
	}

	cred, err := azblob.NewSharedKeyCredential(accountName, accountKey)
	if err != nil {
		return nil, fmt.Errorf("creating Azure credential: %w", err)
	}

	endpoint := fmt.Sprintf("https://%s.blob.core.windows.net", accountName)
	client, err := azblob.NewClientWithSharedKeyCredential(endpoint, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("creating Azure client: %w", err)
	}

	return &AzureBlobService{
		client:    client,
		container: container,
		endpoint:  endpoint,
	}, nil
}

// UploadBytes sube un blob sencillo y retorna la URL pública resultante.
func (s *AzureBlobService) UploadBytes(ctx context.Context, blobName string, data []byte, contentType string) (string, error) {
	if s == nil || s.client == nil {
		return "", fmt.Errorf("azure blob service not configured")
	}
	if blobName == "" {
		return "", fmt.Errorf("blob name is required")
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	ct := contentType

	_, err := s.client.UploadBuffer(ctx, s.container, blobName, data, &azblob.UploadBufferOptions{
		HTTPHeaders: &azblobblob.HTTPHeaders{BlobContentType: &ct},
	})
	if err != nil {
		return "", fmt.Errorf("uploading blob to Azure: %w", err)
	}

	blobsURL, err := url.JoinPath(s.endpoint, s.container, blobName)
	if err != nil {
		return "", err
	}
	return blobsURL, nil
}

// DeleteBlob elimina un blob existente. No falla si el blob no existe.
func (s *AzureBlobService) DeleteBlob(ctx context.Context, blobName string) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("azure blob service not configured")
	}
	blobName = strings.TrimSpace(blobName)
	if blobName == "" {
		return fmt.Errorf("blob name is required")
	}
	_, err := s.client.DeleteBlob(ctx, s.container, blobName, nil)
	return err
}
