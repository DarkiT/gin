package providers

import (
	"testing"

	"github.com/darkit/gin/pkg/sms"
)

func TestNewTencentProviderRequiresAppID(t *testing.T) {
	_, err := NewTencentProvider(sms.SMSConfig{
		Provider:  "tencent",
		AccessKey: "secret-id",
		SecretKey: "secret-key",
		SignName:  "测试签名",
		Region:    "ap-guangzhou",
	})
	if err != sms.ErrSMSAppIDMissing {
		t.Fatalf("应该返回 ErrSMSAppIDMissing，实际: %v", err)
	}
}
