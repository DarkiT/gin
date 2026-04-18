package gin

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/darkit/gin/binding"
	validatorpkg "github.com/darkit/gin/pkg/validator"
)

func TestValidateMobile_Valid(t *testing.T) {
	assert.True(t, validatorpkg.ValidateMobile("13800138000"))
}

func TestValidateMobile_Invalid(t *testing.T) {
	cases := []string{
		"",
		"23800138000",
		"1380013800",
		"138001380000",
		"1380013800a",
	}
	for _, item := range cases {
		assert.False(t, validatorpkg.ValidateMobile(item))
	}
}

func TestValidateIDCard_15Digit(t *testing.T) {
	assert.True(t, validatorpkg.ValidateIDCard("130503670401001"))
	assert.False(t, validatorpkg.ValidateIDCard("13050367040100A"))
}

func TestValidateIDCard_18Digit(t *testing.T) {
	assert.True(t, validatorpkg.ValidateIDCard("11010519491231002X"))
	assert.False(t, validatorpkg.ValidateIDCard("110105194912310021"))
}

func TestValidateIDCard_Checksum(t *testing.T) {
	assert.False(t, validatorpkg.ValidateIDCard("110105194912310020"))
}

func TestValidateBankCard_Luhn(t *testing.T) {
	assert.True(t, validatorpkg.ValidateBankCard("6222027020043917"))
	assert.False(t, validatorpkg.ValidateBankCard("6222027020043918"))
}

func TestValidateUSCC(t *testing.T) {
	assert.True(t, validatorpkg.ValidateUSCC("913502007040810017"))
	assert.False(t, validatorpkg.ValidateUSCC("913502007040810018"))
}

func TestRegisterValidator_Custom(t *testing.T) {
	validatorpkg.RegisterValidator("endswith_a", func(value string) bool {
		return len(value) > 0 && value[len(value)-1] == 'a'
	})

	type customStruct struct {
		Name string `binding:"endswith_a"`
	}

	obj := customStruct{Name: "lina"}

	err := binding.Validator.ValidateStruct(obj)
	assert.NoError(t, err)

	obj.Name = "lin"
	err = binding.Validator.ValidateStruct(obj)
	assert.Error(t, err)
}
