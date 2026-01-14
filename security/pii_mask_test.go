package security

import (
	"testing"
)

func TestMaskEmail(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standard email",
			input:    "john.doe@example.com",
			expected: "jo***@example.com",
		},
		{
			name:     "short local part",
			input:    "jo@example.com",
			expected: "**@example.com",
		},
		{
			name:     "very short local part",
			input:    "j@example.com",
			expected: RedactedEmail,
		},
		{
			name:     "empty email",
			input:    "",
			expected: "",
		},
		{
			name:     "invalid email without @",
			input:    "notanemail",
			expected: RedactedEmail,
		},
		{
			name:     "email with subdomain",
			input:    "user@mail.example.com",
			expected: "us***@mail.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskEmail(tt.input)
			if result != tt.expected {
				t.Errorf("MaskEmail(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMaskPhone(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standard phone",
			input:    "+1-555-123-4567",
			expected: "***4567",
		},
		{
			name:     "phone without country code",
			input:    "5551234567",
			expected: "***4567",
		},
		{
			name:     "phone with spaces",
			input:    "555 123 4567",
			expected: "***4567",
		},
		{
			name:     "empty phone",
			input:    "",
			expected: "",
		},
		{
			name:     "short phone",
			input:    "123",
			expected: RedactedPhone,
		},
		{
			name:     "Indian phone",
			input:    "+91 98765 43210",
			expected: "***3210",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskPhone(tt.input)
			if result != tt.expected {
				t.Errorf("MaskPhone(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMaskName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "full name",
			input:    "John Doe",
			expected: "J*** D***",
		},
		{
			name:     "single name",
			input:    "John",
			expected: "J***",
		},
		{
			name:     "three part name",
			input:    "John Michael Doe",
			expected: "J*** M*** D***",
		},
		{
			name:     "empty name",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskName(tt.input)
			if result != tt.expected {
				t.Errorf("MaskName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMaskCard(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "visa card",
			input:    "4111111111111111",
			expected: "****1111",
		},
		{
			name:     "card with spaces",
			input:    "4111 1111 1111 1111",
			expected: "****1111",
		},
		{
			name:     "card with dashes",
			input:    "4111-1111-1111-1111",
			expected: "****1111",
		},
		{
			name:     "empty card",
			input:    "",
			expected: "",
		},
		{
			name:     "short number",
			input:    "123",
			expected: RedactedCard,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskCard(tt.input)
			if result != tt.expected {
				t.Errorf("MaskCard(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMaskPAN(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid PAN",
			input:    "ABCDE1234F",
			expected: "ABCD***34F",
		},
		{
			name:     "lowercase PAN",
			input:    "abcde1234f",
			expected: "ABCD***34F",
		},
		{
			name:     "empty PAN",
			input:    "",
			expected: "",
		},
		{
			name:     "invalid length",
			input:    "ABC123",
			expected: RedactedPAN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskPAN(tt.input)
			if result != tt.expected {
				t.Errorf("MaskPAN(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMaskGSTIN(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid GSTIN",
			input:    "29ABCDE1234F1Z5",
			expected: "29****4F1Z5",
		},
		{
			name:     "empty GSTIN",
			input:    "",
			expected: "",
		},
		{
			name:     "invalid length",
			input:    "29ABC",
			expected: RedactedGSTIN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskGSTIN(tt.input)
			if result != tt.expected {
				t.Errorf("MaskGSTIN(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMaskVerificationCode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "6 digit code",
			input:    "123456",
			expected: RedactedCode,
		},
		{
			name:     "4 digit code",
			input:    "1234",
			expected: RedactedCode,
		},
		{
			name:     "empty code",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskVerificationCode(tt.input)
			if result != tt.expected {
				t.Errorf("MaskVerificationCode(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeLogMessage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
		notContains string
	}{
		{
			name:        "message with email",
			input:       "User john.doe@example.com logged in",
			contains:    "jo***@example.com",
			notContains: "john.doe@example.com",
		},
		{
			name:        "message with PAN",
			input:       "PAN verified: ABCDE1234F",
			contains:    "ABCD***34F",
			notContains: "ABCDE1234F",
		},
		{
			name:        "plain message",
			input:       "User logged in successfully",
			contains:    "User logged in successfully",
			notContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeLogMessage(tt.input)
			if tt.contains != "" && !containsString(result, tt.contains) {
				t.Errorf("SanitizeLogMessage(%q) should contain %q, got %q", tt.input, tt.contains, result)
			}
			if tt.notContains != "" && containsString(result, tt.notContains) {
				t.Errorf("SanitizeLogMessage(%q) should not contain %q, got %q", tt.input, tt.notContains, result)
			}
		})
	}
}

func TestSecureLogFields(t *testing.T) {
	input := map[string]interface{}{
		"email":      "john@example.com",
		"phone":      "+1-555-123-4567",
		"name":       "John Doe",
		"order_id":   "12345",
		"password":   "secret123",
		"code":       "123456",
	}

	result := SecureLogFields(input)

	// Check email is masked
	if email, ok := result["email"].(string); ok {
		if email == "john@example.com" {
			t.Error("Email should be masked")
		}
		if email != "jo***@example.com" {
			t.Errorf("Email mask incorrect: got %q", email)
		}
	}

	// Check phone is masked
	if phone, ok := result["phone"].(string); ok {
		if phone == "+1-555-123-4567" {
			t.Error("Phone should be masked")
		}
	}

	// Check name is masked
	if name, ok := result["name"].(string); ok {
		if name == "John Doe" {
			t.Error("Name should be masked")
		}
	}

	// Check order_id is NOT masked (not PII)
	if orderID, ok := result["order_id"].(string); ok {
		if orderID != "12345" {
			t.Error("Non-PII fields should not be modified")
		}
	}

	// Check password is redacted
	if password, ok := result["password"].(string); ok {
		if password != "[REDACTED]" {
			t.Errorf("Password should be [REDACTED], got %q", password)
		}
	}

	// Check code is redacted
	if code, ok := result["code"].(string); ok {
		if code != RedactedCode {
			t.Errorf("Code should be %q, got %q", RedactedCode, code)
		}
	}
}

func containsString(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) && (s == substr || containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
