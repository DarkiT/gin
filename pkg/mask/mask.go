// Package mask 提供基于标签的通用脱敏能力。
package mask

import (
	"reflect"
	"sync"
)

// MaskFunc 表示脱敏函数签名。
type MaskFunc func(value string) string

// MaskOption 表示脱敏配置选项。
type MaskOption func(*maskOptions)

type maskOptions struct {
	maskChar rune
	rules    map[string]MaskFunc
	custom   map[string]MaskFunc
}

var (
	rulesMu       sync.RWMutex
	defaultRules  = make(map[string]MaskFunc)
	userOverrides = make(map[string]bool)
	defaultOption = maskOptions{maskChar: '*'}
	typeCache     sync.Map
)

type fieldMaskInfo struct {
	Index    int
	MaskTag  string
	IsString bool
}

func registerBuiltinMaskFunc(tag string, fn MaskFunc) {
	if tag == "" || fn == nil {
		return
	}
	rulesMu.Lock()
	defaultRules[tag] = fn
	rulesMu.Unlock()
}

// RegisterMaskFunc 注册自定义脱敏规则。
func RegisterMaskFunc(tag string, fn MaskFunc) {
	if tag == "" || fn == nil {
		return
	}
	rulesMu.Lock()
	defaultRules[tag] = fn
	userOverrides[tag] = true
	rulesMu.Unlock()
}

// WithMaskChar 设置脱敏字符。
func WithMaskChar(char rune) MaskOption {
	return func(opt *maskOptions) {
		if opt == nil {
			return
		}
		opt.maskChar = char
	}
}

// WithMaskRules 合并自定义脱敏规则。
func WithMaskRules(rules map[string]MaskFunc) MaskOption {
	return func(opt *maskOptions) {
		if opt == nil || len(rules) == 0 {
			return
		}
		if opt.custom == nil {
			opt.custom = make(map[string]MaskFunc, len(rules))
		}
		for key, fn := range rules {
			if key == "" || fn == nil {
				continue
			}
			opt.custom[key] = fn
		}
	}
}

// MaskValue 根据标签对数据进行脱敏，返回新的副本。
func MaskValue(value any, opts ...MaskOption) any {
	if value == nil {
		return nil
	}
	options := buildOptions(opts...)
	val := reflect.ValueOf(value)
	masked := maskValue(val, options)
	return masked.Interface()
}

func buildOptions(opts ...MaskOption) *maskOptions {
	options := &maskOptions{
		maskChar: defaultOption.maskChar,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(options)
		}
	}
	rulesMu.RLock()
	localRules := make(map[string]MaskFunc, len(defaultRules))
	for k, v := range defaultRules {
		localRules[k] = v
	}
	localOverrides := make(map[string]bool, len(userOverrides))
	for k, v := range userOverrides {
		localOverrides[k] = v
	}
	rulesMu.RUnlock()
	if options.maskChar != defaultOption.maskChar {
		for tag, fn := range buildBuiltinRules(options.maskChar) {
			if localOverrides[tag] {
				continue
			}
			localRules[tag] = fn
		}
	}
	if len(options.custom) > 0 {
		for tag, fn := range options.custom {
			localRules[tag] = fn
		}
	}
	options.rules = localRules
	return options
}

func maskValue(val reflect.Value, options *maskOptions) reflect.Value {
	if !val.IsValid() {
		return val
	}
	switch val.Kind() {
	case reflect.Interface:
		if val.IsNil() {
			return val
		}
		return maskValue(val.Elem(), options)
	case reflect.Pointer:
		if val.IsNil() {
			return val
		}
		maskedElem := maskValue(val.Elem(), options)
		ptr := reflect.New(val.Type().Elem())
		ptr.Elem().Set(maskedElem)
		return ptr
	}
	switch val.Kind() {
	case reflect.Struct:
		return maskStruct(val, options)
	case reflect.Slice, reflect.Array:
		return maskSlice(val, options)
	case reflect.Map:
		return maskMap(val, options)
	default:
		return val
	}
}

func maskStruct(val reflect.Value, options *maskOptions) reflect.Value {
	masked := reflect.New(val.Type()).Elem()
	infos := getFieldMaskInfo(val.Type())
	for _, info := range infos {
		field := val.Field(info.Index)
		if info.MaskTag != "" && info.IsString {
			maskedValue := applyMaskRule(field.String(), info.MaskTag, options)
			masked.Field(info.Index).SetString(maskedValue)
			continue
		}
		maskedField := maskValue(field, options)
		masked.Field(info.Index).Set(maskedField)
	}
	return masked
}

func maskSlice(val reflect.Value, options *maskOptions) reflect.Value {
	masked := reflect.MakeSlice(val.Type(), val.Len(), val.Cap())
	for i := 0; i < val.Len(); i++ {
		item := val.Index(i)
		maskedItem := maskValue(item, options)
		masked.Index(i).Set(maskedItem)
	}
	return masked
}

func maskMap(val reflect.Value, options *maskOptions) reflect.Value {
	if val.IsNil() {
		return val
	}
	masked := reflect.MakeMapWithSize(val.Type(), val.Len())
	iter := val.MapRange()
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()
		maskedValue := maskValue(value, options)
		masked.SetMapIndex(key, maskedValue)
	}
	return masked
}

func applyMaskRule(value string, tag string, options *maskOptions) string {
	if options == nil || options.rules == nil {
		return value
	}
	fn, ok := options.rules[tag]
	if !ok || fn == nil {
		return value
	}
	return fn(value)
}

func getFieldMaskInfo(t reflect.Type) []fieldMaskInfo {
	if cached, ok := typeCache.Load(t); ok {
		return cached.([]fieldMaskInfo)
	}
	info := parseType(t)
	actual, _ := typeCache.LoadOrStore(t, info)
	return actual.([]fieldMaskInfo)
}

func parseType(t reflect.Type) []fieldMaskInfo {
	fieldCount := t.NumField()
	infos := make([]fieldMaskInfo, 0, fieldCount)
	for i := 0; i < fieldCount; i++ {
		fieldType := t.Field(i)
		if fieldType.PkgPath != "" {
			continue
		}
		infos = append(infos, fieldMaskInfo{
			Index:    i,
			MaskTag:  fieldType.Tag.Get("mask"),
			IsString: fieldType.Type.Kind() == reflect.String,
		})
	}
	return infos
}
