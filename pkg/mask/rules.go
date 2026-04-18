package mask

import (
	"strings"
)

func init() {
	registerBuiltinMaskFunc("mobile", MaskMobile)
	registerBuiltinMaskFunc("email", MaskEmail)
	registerBuiltinMaskFunc("idcard", MaskIDCard)
	registerBuiltinMaskFunc("bankcard", MaskBankCard)
	registerBuiltinMaskFunc("name", MaskName)
	registerBuiltinMaskFunc("address", MaskAddress)
}

// MaskMobile 手机号脱敏：138****8888。
func MaskMobile(mobile string) string {
	return maskMobile(mobile, '*')
}

// MaskEmail 邮箱脱敏：a***@example.com。
func MaskEmail(email string) string {
	return maskEmail(email, '*')
}

// MaskIDCard 身份证脱敏：110***********1234。
func MaskIDCard(idcard string) string {
	return maskIDCard(idcard, '*')
}

// MaskBankCard 银行卡脱敏：6222****1234。
func MaskBankCard(cardNo string) string {
	return maskBankCard(cardNo, '*')
}

// MaskName 姓名脱敏：张*。
func MaskName(name string) string {
	return maskName(name, '*')
}

// MaskAddress 地址脱敏：北京市***。
func MaskAddress(address string) string {
	return maskAddress(address, '*')
}

func maskMobile(mobile string, maskChar rune) string {
	mobile = strings.TrimSpace(mobile)
	if len(mobile) < 7 {
		return maskAllWithChar(mobile, maskChar)
	}
	return mobile[:3] + strings.Repeat(string(maskChar), len(mobile)-7) + mobile[len(mobile)-4:]
}

func maskEmail(email string, maskChar rune) string {
	email = strings.TrimSpace(email)
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[0] == "" {
		return maskAllWithChar(email, maskChar)
	}
	local := parts[0]
	domain := parts[1]
	if len(local) == 1 {
		return local + strings.Repeat(string(maskChar), 3) + "@" + domain
	}
	return local[:1] + strings.Repeat(string(maskChar), 3) + "@" + domain
}

func maskIDCard(idcard string, maskChar rune) string {
	idcard = strings.TrimSpace(idcard)
	if len(idcard) <= 8 {
		return maskAllWithChar(idcard, maskChar)
	}
	return idcard[:3] + strings.Repeat(string(maskChar), len(idcard)-7) + idcard[len(idcard)-4:]
}

func maskBankCard(cardNo string, maskChar rune) string {
	cardNo = strings.TrimSpace(cardNo)
	if len(cardNo) <= 8 {
		return maskAllWithChar(cardNo, maskChar)
	}
	return cardNo[:4] + strings.Repeat(string(maskChar), len(cardNo)-8) + cardNo[len(cardNo)-4:]
}

func maskName(name string, maskChar rune) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	runes := []rune(name)
	if len(runes) <= 1 {
		return string(runes)
	}
	return string(runes[0]) + strings.Repeat(string(maskChar), len(runes)-1)
}

func maskAddress(address string, maskChar rune) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}
	runes := []rune(address)
	if len(runes) <= 3 {
		return string(runes) + strings.Repeat(string(maskChar), 3)
	}
	return string(runes[:3]) + strings.Repeat(string(maskChar), 3)
}

func maskAllWithChar(value string, maskChar rune) string {
	if value == "" {
		return ""
	}
	return strings.Repeat(string(maskChar), len([]rune(value)))
}

func buildBuiltinRules(maskChar rune) map[string]MaskFunc {
	return map[string]MaskFunc{
		"mobile":   func(value string) string { return maskMobile(value, maskChar) },
		"email":    func(value string) string { return maskEmail(value, maskChar) },
		"idcard":   func(value string) string { return maskIDCard(value, maskChar) },
		"bankcard": func(value string) string { return maskBankCard(value, maskChar) },
		"name":     func(value string) string { return maskName(value, maskChar) },
		"address":  func(value string) string { return maskAddress(value, maskChar) },
	}
}
