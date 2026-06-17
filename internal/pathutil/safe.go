package pathutil

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
)

var (
	// ErrInvalidPath 表示路径非法或不符合安全约束。
	ErrInvalidPath = errors.New("非法路径")
	// ErrPathEscape 表示路径试图越过基础目录。
	ErrPathEscape = errors.New("路径越界")
)

// SafePath 验证用户路径是否在 baseDir 内。
func SafePath(baseDir, userPath string) (string, error) {
	base := filepath.Clean(baseDir)
	if base == "." || base == "" {
		return "", ErrInvalidPath
	}

	trimmed := strings.TrimSpace(userPath)
	if trimmed == "" {
		return "", ErrInvalidPath
	}
	if strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "\\\\") {
		return "", ErrInvalidPath
	}
	if isWindowsDrivePath(trimmed) {
		return "", ErrInvalidPath
	}

	segments := strings.FieldsFunc(trimmed, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	if slices.Contains(segments, "..") {
		return "", ErrInvalidPath
	}

	clean := filepath.Clean(trimmed)
	if clean == "." || clean == "" {
		return "", ErrInvalidPath
	}
	if filepath.IsAbs(clean) {
		return "", ErrInvalidPath
	}

	full := filepath.Clean(filepath.Join(base, clean))
	rel, err := filepath.Rel(base, full)
	if err != nil {
		return "", ErrInvalidPath
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", ErrPathEscape
	}

	return full, nil
}

// SafeTemplateName 校验模板名称是否合法。
func SafeTemplateName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ErrInvalidPath
	}
	if strings.ContainsAny(trimmed, "\\/") {
		return ErrInvalidPath
	}
	if strings.Contains(trimmed, "..") {
		return ErrInvalidPath
	}
	return nil
}

func isWindowsDrivePath(path string) bool {
	if len(path) < 2 {
		return false
	}
	if path[1] != ':' {
		return false
	}
	return unicode.IsLetter(rune(path[0]))
}
