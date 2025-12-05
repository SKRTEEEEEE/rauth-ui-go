package utils

import (
	"fmt"
	"log"
	"net/smtp"
	"os"
)

// SendVerificationEmail sends an email with verification token
func SendVerificationEmail(email, token string) error {
	// Get SMTP configuration from environment
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUsername := os.Getenv("SMTP_USERNAME")
	smtpPassword := os.Getenv("SMTP_PASSWORD")
	smtpFrom := os.Getenv("SMTP_FROM")

	// If SMTP is not configured, log the token instead (development mode)
	if smtpHost == "" || smtpPort == "" {
		log.Printf("📧 [DEV MODE] Email verification token for %s: %s", email, token)
		log.Printf("📧 [DEV MODE] Verification link: %s/api/v1/auth/verify-email?token=%s", 
			getBaseURL(), token)
		return nil
	}

	// Build verification link
	verificationLink := fmt.Sprintf("%s/api/v1/auth/verify-email?token=%s", getBaseURL(), token)

	// Compose email
	subject := "Verify your email address"
	body := fmt.Sprintf(`Hello,

Please click the link below to verify your email address:

%s

This link will expire in 24 hours.

If you didn't request this verification, please ignore this email.

Best regards,
RAuth Team`, verificationLink)

	// Send email via SMTP
	return sendSMTP(smtpHost, smtpPort, smtpUsername, smtpPassword, smtpFrom, email, subject, body)
}

// SendPasswordResetEmail sends an email with password reset token
func SendPasswordResetEmail(email, token string) error {
	// Get SMTP configuration from environment
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUsername := os.Getenv("SMTP_USERNAME")
	smtpPassword := os.Getenv("SMTP_PASSWORD")
	smtpFrom := os.Getenv("SMTP_FROM")

	// If SMTP is not configured, log the token instead (development mode)
	if smtpHost == "" || smtpPort == "" {
		log.Printf("📧 [DEV MODE] Password reset token for %s: %s", email, token)
		log.Printf("📧 [DEV MODE] Reset link: %s/api/v1/auth/reset-password?token=%s", 
			getBaseURL(), token)
		return nil
	}

	// Build reset link
	resetLink := fmt.Sprintf("%s/api/v1/auth/reset-password?token=%s", getBaseURL(), token)

	// Compose email
	subject := "Reset your password"
	body := fmt.Sprintf(`Hello,

You requested to reset your password. Click the link below to continue:

%s

This link will expire in 1 hour.

If you didn't request a password reset, please ignore this email and your password will remain unchanged.

Best regards,
RAuth Team`, resetLink)

	// Send email via SMTP
	return sendSMTP(smtpHost, smtpPort, smtpUsername, smtpPassword, smtpFrom, email, subject, body)
}

// sendSMTP sends an email via SMTP
func sendSMTP(host, port, username, password, from, to, subject, body string) error {
	// Setup authentication
	auth := smtp.PlainAuth("", username, password, host)

	// Compose message
	msg := []byte(fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"\r\n"+
		"%s\r\n", from, to, subject, body))

	// Send email
	addr := fmt.Sprintf("%s:%s", host, port)
	err := smtp.SendMail(addr, auth, from, []string{to}, msg)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Printf("📧 Email sent successfully to %s", to)
	return nil
}

// getBaseURL returns the base URL for the application
func getBaseURL() string {
	platformURL := os.Getenv("PLATFORM_URL")
	if platformURL == "" {
		platformURL = "http://localhost:8080"
	}
	return platformURL
}
