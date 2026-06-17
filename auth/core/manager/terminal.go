package manager

import (
	"slices"
	"strings"
)

// GetTerminalListByLoginID lists device suffixes; filters by device when provided | 终端列表，可按 device 过滤
func (m *Manager) GetTerminalListByLoginID(loginID string, device ...string) ([]string, error) {
	pattern := m.prefix + AccountKeyPrefix + loginID + ":*"
	keys, err := m.storage.Keys(pattern)
	if err != nil {
		return nil, err
	}
	pref := m.prefix + AccountKeyPrefix + loginID + ":"
	wantDev := ""
	if len(device) > 0 {
		wantDev = device[0]
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		dev := strings.TrimPrefix(k, pref)
		if wantDev != "" && dev != wantDev {
			continue
		}
		out = append(out, dev)
	}
	return out, nil
}

// GetTerminalInfo is an alias of GetTokenInfo | 终端信息（同 TokenInfo）
func (m *Manager) GetTerminalInfo(tokenValue string) (*TokenInfo, error) {
	return m.GetTokenInfo(tokenValue)
}

// GetLoginDeviceType returns device tag from token | 登录设备类型
func (m *Manager) GetLoginDeviceType(tokenValue string) (string, error) {
	info, err := m.getTokenInfo(tokenValue)
	if err != nil {
		return "", err
	}
	if info == nil {
		return "", ErrInvalidTokenData
	}
	return info.Device, nil
}

// GetLoginDeviceID returns device id (same as device tag in this implementation) | 登录设备 ID
func (m *Manager) GetLoginDeviceID(tokenValue string) (string, error) {
	return m.GetLoginDeviceType(tokenValue)
}

const trustDeviceIDsKey = "trustDeviceIds"

// IsTrustDeviceID checks Account-Session trustDeviceIds list | 是否信任设备
func (m *Manager) IsTrustDeviceID(loginID, deviceID string) bool {
	if loginID == "" || deviceID == "" {
		return false
	}
	sess, err := m.GetSession(loginID)
	if err != nil || sess == nil {
		return false
	}
	raw, ok := sess.Get(trustDeviceIDsKey)
	if !ok || raw == nil {
		return false
	}
	switch v := raw.(type) {
	case []string:
		if slices.Contains(v, deviceID) {
			return true
		}
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && s == deviceID {
				return true
			}
		}
	}
	return false
}

// AddTrustDeviceID appends a trusted device id on Account-Session | 添加信任设备
func (m *Manager) AddTrustDeviceID(loginID, deviceID string) error {
	sess, err := m.GetSession(loginID)
	if err != nil || sess == nil {
		return err
	}
	list := []string{}
	if raw, ok := sess.Get(trustDeviceIDsKey); ok {
		switch v := raw.(type) {
		case []string:
			list = v
		case []any:
			for _, x := range v {
				if s, ok := x.(string); ok {
					list = append(list, s)
				}
			}
		}
	}
	if slices.Contains(list, deviceID) {
		return nil
	}
	list = append(list, deviceID)
	return sess.Set(trustDeviceIDsKey, list)
}
