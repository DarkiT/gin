package validator

import (
	"sync"

	"github.com/darkit/gin/binding"
	"github.com/go-playground/validator/v10"
)

// ValidatorFunc 验证函数类型。
type ValidatorFunc func(value string) bool

var (
	validatorOnce sync.Once
	validatorMu   sync.Mutex
	validators    = make(map[string]ValidatorFunc)
)

// RegisterValidator 注册自定义验证规则。
func RegisterValidator(tag string, fn ValidatorFunc) {
	if tag == "" || fn == nil {
		return
	}
	validatorMu.Lock()
	validators[tag] = fn
	validatorMu.Unlock()
	ensureValidatorsRegistered()
	registerValidatorWithEngine(tag, fn)
}

func init() {
	validatorMu.Lock()
	validators["mobile"] = ValidateMobile
	validators["idcard"] = ValidateIDCard
	validators["bankcard"] = ValidateBankCard
	validators["uscc"] = ValidateUSCC
	validatorMu.Unlock()
	ensureValidatorsRegistered()
}

func ensureValidatorsRegistered() {
	ensureBindingValidator()
	validatorOnce.Do(func() {
		validatorMu.Lock()
		local := make(map[string]ValidatorFunc, len(validators))
		for tag, fn := range validators {
			local[tag] = fn
		}
		validatorMu.Unlock()
		for tag, fn := range local {
			registerValidatorWithEngine(tag, fn)
		}
	})
}

func ensureBindingValidator() {
	if binding.Validator == nil {
		binding.Validator = &bindingDefaultValidator{}
	}
}

type bindingDefaultValidator struct {
	inner *validator.Validate
	mu    sync.Mutex
}

func (v *bindingDefaultValidator) ValidateStruct(obj any) error {
	engine := v.Engine().(*validator.Validate)
	return engine.Struct(obj)
}

func (v *bindingDefaultValidator) Engine() any {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.inner == nil {
		v.inner = validator.New()
		v.inner.SetTagName("binding")
	}
	return v.inner
}

func registerValidatorWithEngine(tag string, fn ValidatorFunc) {
	engine, ok := binding.Validator.Engine().(*validator.Validate)
	if !ok || engine == nil {
		return
	}
	_ = engine.RegisterValidation(tag, func(fl validator.FieldLevel) bool {
		value, ok := fl.Field().Interface().(string)
		if !ok {
			return false
		}
		return fn(value)
	})
}

// EnsureValidators 注册内置与已注册的自定义验证规则到 gin validator。
func EnsureValidators() {
	ensureValidatorsRegistered()
}
