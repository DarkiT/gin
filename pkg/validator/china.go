package validator

import "strings"

var (
	usccCharset       = []byte("0123456789ABCDEFGHJKLMNPQRTUWXY")
	usccWeights       = []int{1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28}
	idCardWeights     = []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	idCardChecksumMap = []byte{'1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'}
)

// ValidateMobile 校验手机号：11 位，1 开头。
func ValidateMobile(mobile string) bool {
	mobile = strings.TrimSpace(mobile)
	if len(mobile) != 11 {
		return false
	}
	if mobile[0] != '1' {
		return false
	}
	for i := 0; i < len(mobile); i++ {
		ch := mobile[i]
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// ValidateIDCard 校验身份证：15/18 位，18 位含校验位。
func ValidateIDCard(idcard string) bool {
	idcard = strings.TrimSpace(idcard)
	switch len(idcard) {
	case 15:
		return validateIDCard15(idcard)
	case 18:
		return validateIDCard18(idcard)
	default:
		return false
	}
}

// ValidateBankCard 校验银行卡：Luhn 算法。
func ValidateBankCard(cardNo string) bool {
	cardNo = strings.TrimSpace(cardNo)
	if len(cardNo) == 0 {
		return false
	}
	return luhnCheck(cardNo)
}

// ValidateUSCC 校验统一社会信用代码：18 位。
func ValidateUSCC(code string) bool {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 18 {
		return false
	}
	for i := range 17 {
		if usccCharIndex(code[i]) < 0 {
			return false
		}
	}
	check := code[17]
	if usccCharIndex(check) < 0 {
		return false
	}
	return check == calculateUSCCChecksum(code[:17])
}

func validateIDCard15(id string) bool {
	for i := range 15 {
		if id[i] < '0' || id[i] > '9' {
			return false
		}
	}
	return true
}

func validateIDCard18(id string) bool {
	for i := range 17 {
		if id[i] < '0' || id[i] > '9' {
			return false
		}
	}
	last := id[17]
	if (last < '0' || last > '9') && last != 'X' && last != 'x' {
		return false
	}
	return strings.ToUpper(string(last)) == calculateIDCardChecksum(id)
}

func calculateIDCardChecksum(id string) string {
	if len(id) < 17 {
		return ""
	}
	sum := 0
	for i := range 17 {
		ch := id[i]
		if ch < '0' || ch > '9' {
			return ""
		}
		sum += int(ch-'0') * idCardWeights[i]
	}
	return string(idCardChecksumMap[sum%11])
}

func calculateUSCCChecksum(code17 string) byte {
	sum := 0
	for i := range 17 {
		idx := usccCharIndex(code17[i])
		if idx < 0 {
			return 0
		}
		sum += idx * usccWeights[i]
	}
	mod := sum % 31
	check := (31 - mod) % 31
	return usccCharset[check]
}

func usccCharIndex(ch byte) int {
	for i, val := range usccCharset {
		if val == ch {
			return i
		}
	}
	return -1
}
