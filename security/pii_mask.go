package security

import (
	"regexp"
	"strings"
)

// PII Masking Constants
const (
	RedactedEmail   = "[EMAIL_REDACTED]"
	RedactedPhone   = "[PHONE_REDACTED]"
	RedactedName    = "[NAME_REDACTED]"
	RedactedAddress = "[ADDRESS_REDACTED]"
	RedactedCode    = "[CODE_REDACTED]"
	RedactedCard    = "[CARD_REDACTED]"
	RedactedSSN     = "[SSN_REDACTED]"
	RedactedPAN     = "[PAN_REDACTED]"
	RedactedGSTIN   = "[GSTIN_REDACTED]"
)

// Regular expression patterns for PII detection
var (
	emailPattern   = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	phonePattern   = regexp.MustCompile(`(?:\+?[0-9]{1,4}[\s\-]?)?(?:\([0-9]{1,4}\)[\s\-]?)?[0-9]{6,14}`)
	cardPattern    = regexp.MustCompile(`[0-9]{13,19}`)
	ssnPattern     = regexp.MustCompile(`[0-9]{3}[\-\s]?[0-9]{2}[\-\s]?[0-9]{4}`)
	panPattern     = regexp.MustCompile(`[A-Z]{5}[0-9]{4}[A-Z]`)
	gstinPattern   = regexp.MustCompile(`[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][A-Z0-9][Z][A-Z0-9]`)
	otpCodePattern = regexp.MustCompile(`\b[0-9]{4,8}\b`)
)

// MaskEmail masks an email address for logging
// Shows first 2 characters and domain
// Example: jo***@example.com
func MaskEmail(email string) string {
	if email == "" {
		return ""
	}

	atIndex := strings.LastIndex(email, "@")
	if atIndex == -1 || atIndex < 2 {
		return RedactedEmail
	}

	localPart := email[:atIndex]
	domain := email[atIndex:]

	if len(localPart) <= 2 {
		return "**" + domain
	}

	return localPart[:2] + "***" + domain
}

// MaskPhone masks a phone number for logging
// Shows last 4 digits only
// Example: ***1234
func MaskPhone(phone string) string {
	if phone == "" {
		return ""
	}

	// Remove non-digit characters for length check
	digitsOnly := regexp.MustCompile(`[^0-9]`).ReplaceAllString(phone, "")

	if len(digitsOnly) < 4 {
		return RedactedPhone
	}

	return "***" + digitsOnly[len(digitsOnly)-4:]
}

// MaskName masks a name for logging
// Shows first character of first and last name
// Example: J*** D***
func MaskName(name string) string {
	if name == "" {
		return ""
	}

	parts := strings.Fields(name)
	if len(parts) == 0 {
		return RedactedName
	}

	var masked []string
	for _, part := range parts {
		if len(part) > 0 {
			masked = append(masked, string(part[0])+"***")
		}
	}

	return strings.Join(masked, " ")
}

// MaskAddress masks an address for logging
// Shows only city/country level
func MaskAddress(address string) string {
	if address == "" {
		return ""
	}

	// For addresses, we completely redact to be safe
	return RedactedAddress
}

// MaskCard masks a credit/debit card number
// Shows last 4 digits only
// Example: ****1234
func MaskCard(cardNumber string) string {
	if cardNumber == "" {
		return ""
	}

	digitsOnly := regexp.MustCompile(`[^0-9]`).ReplaceAllString(cardNumber, "")

	if len(digitsOnly) < 4 {
		return RedactedCard
	}

	return "****" + digitsOnly[len(digitsOnly)-4:]
}

// MaskPAN masks an Indian PAN number
// Example: ABCD***90A
func MaskPAN(pan string) string {
	if pan == "" {
		return ""
	}

	pan = strings.ToUpper(strings.TrimSpace(pan))
	if len(pan) != 10 {
		return RedactedPAN
	}

	return pan[:4] + "***" + pan[7:]
}

// MaskGSTIN masks an Indian GSTIN
// Example: 29****4D1ZK
func MaskGSTIN(gstin string) string {
	if gstin == "" {
		return ""
	}

	gstin = strings.ToUpper(strings.TrimSpace(gstin))
	if len(gstin) != 15 {
		return RedactedGSTIN
	}

	return gstin[:2] + "****" + gstin[10:]
}

// MaskVerificationCode completely redacts verification codes
// Verification codes should NEVER appear in logs
func MaskVerificationCode(code string) string {
	if code == "" {
		return ""
	}
	return RedactedCode
}

// MaskUserID partially masks a user ID
// Shows first 8 characters only
// Example: 12345678-****
func MaskUserID(userID string) string {
	if userID == "" {
		return ""
	}

	if len(userID) <= 8 {
		return userID[:len(userID)/2] + "****"
	}

	return userID[:8] + "-****"
}

// SanitizeLogMessage scans a log message for PII and masks it
// This is a safety net for any PII that might slip through
func SanitizeLogMessage(message string) string {
	if message == "" {
		return message
	}

	// Mask emails
	message = emailPattern.ReplaceAllStringFunc(message, func(email string) string {
		return MaskEmail(email)
	})

	// Mask phone numbers (be careful with this - might match other numbers)
	// Only match patterns that look like phone numbers
	phoneMatches := phonePattern.FindAllString(message, -1)
	for _, phone := range phoneMatches {
		// Only mask if it looks like a phone number (10+ digits)
		digitsOnly := regexp.MustCompile(`[^0-9]`).ReplaceAllString(phone, "")
		if len(digitsOnly) >= 10 && len(digitsOnly) <= 15 {
			message = strings.Replace(message, phone, MaskPhone(phone), 1)
		}
	}

	// Mask PAN numbers
	message = panPattern.ReplaceAllStringFunc(message, func(pan string) string {
		return MaskPAN(pan)
	})

	// Mask GSTIN numbers
	message = gstinPattern.ReplaceAllStringFunc(message, func(gstin string) string {
		return MaskGSTIN(gstin)
	})

	return message
}

// PIISafeString wraps a string that should be safe to log
// Use this to mark strings that have already been sanitized
type PIISafeString string

// Safe marks a string as PII-safe (use with caution)
func Safe(s string) PIISafeString {
	return PIISafeString(s)
}

// LogContext holds context information for secure logging
type LogContext struct {
	TenantID  string
	UserID    string
	RequestID string
	Operation string
}

// SecureLogFields creates a map of fields safe for logging
// It automatically masks PII fields if included
func SecureLogFields(fields map[string]interface{}) map[string]interface{} {
	safeFields := make(map[string]interface{})

	for key, value := range fields {
		switch strings.ToLower(key) {
		case "email", "user_email", "customer_email", "to", "from":
			if email, ok := value.(string); ok {
				safeFields[key] = MaskEmail(email)
			} else {
				safeFields[key] = RedactedEmail
			}
		case "phone", "mobile", "phone_number", "mobile_number":
			if phone, ok := value.(string); ok {
				safeFields[key] = MaskPhone(phone)
			} else {
				safeFields[key] = RedactedPhone
			}
		case "name", "first_name", "last_name", "full_name", "customer_name":
			if name, ok := value.(string); ok {
				safeFields[key] = MaskName(name)
			} else {
				safeFields[key] = RedactedName
			}
		case "address", "street", "street_address", "billing_address", "shipping_address":
			safeFields[key] = RedactedAddress
		case "code", "verification_code", "otp", "pin", "secret":
			safeFields[key] = RedactedCode
		case "card", "card_number", "credit_card", "debit_card":
			if card, ok := value.(string); ok {
				safeFields[key] = MaskCard(card)
			} else {
				safeFields[key] = RedactedCard
			}
		case "pan", "pan_number":
			if pan, ok := value.(string); ok {
				safeFields[key] = MaskPAN(pan)
			} else {
				safeFields[key] = RedactedPAN
			}
		case "gstin", "gst_number":
			if gstin, ok := value.(string); ok {
				safeFields[key] = MaskGSTIN(gstin)
			} else {
				safeFields[key] = RedactedGSTIN
			}
		case "password", "current_password", "new_password", "old_password":
			safeFields[key] = "[REDACTED]"
		default:
			// For string values, sanitize the content
			if str, ok := value.(string); ok {
				safeFields[key] = SanitizeLogMessage(str)
			} else {
				safeFields[key] = value
			}
		}
	}

	return safeFields
}
