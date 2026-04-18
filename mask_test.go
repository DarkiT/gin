package gin_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	engine "github.com/darkit/gin"
	"github.com/darkit/gin/pkg/mask"
)

func TestMaskMobile(t *testing.T) {
	assert.Equal(t, "138****8000", mask.MaskMobile("13800138000"))
}

func TestMaskEmail(t *testing.T) {
	assert.Equal(t, "t***@example.com", mask.MaskEmail("test@example.com"))
}

func TestMaskIDCard(t *testing.T) {
	assert.Equal(t, "110***********1234", mask.MaskIDCard("110105194912311234"))
}

func TestMaskBankCard(t *testing.T) {
	assert.Equal(t, "6222********1234", mask.MaskBankCard("6222334455661234"))
}

func TestMaskName(t *testing.T) {
	assert.Equal(t, "张*", mask.MaskName("张三"))
}

func TestOKMasked_Struct(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodGet, "/", "")
	ctx.OKMasked(testUser{Mobile: "13800138000"})
	if w.Code != http.StatusOK {
		t.Fatalf("ok masked status")
	}
	var resp engine.Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode ok masked: %v", err)
	}
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("masked data type")
	}
	if data["mobile"] != "138****8000" {
		t.Fatalf("masked mobile")
	}
}

func TestOKMasked_NestedStruct(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodGet, "/", "")
	payload := nestedUser{
		Profile: testUser{
			Mobile: "13800138000",
			Email:  "test@example.com",
		},
	}
	ctx.OKMasked(payload)
	var resp engine.Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode ok masked: %v", err)
	}
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("masked data type")
	}
	profile, ok := data["profile"].(map[string]any)
	if !ok {
		t.Fatalf("masked profile type")
	}
	if profile["mobile"] != "138****8000" {
		t.Fatalf("masked nested mobile")
	}
	if profile["email"] != "t***@example.com" {
		t.Fatalf("masked nested email")
	}
}

func TestOKMasked_Slice(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodGet, "/", "")
	users := []testUser{
		{Mobile: "13800138000"},
		{Mobile: "13900139000"},
	}
	ctx.OKMasked(users)
	var resp engine.Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode ok masked: %v", err)
	}
	list, ok := resp.Data.([]any)
	if !ok {
		t.Fatalf("masked list type")
	}
	if len(list) != 2 {
		t.Fatalf("masked list length")
	}
	first, ok := list[0].(map[string]any)
	if !ok {
		t.Fatalf("masked list item type")
	}
	if first["mobile"] != "138****8000" {
		t.Fatalf("masked list mobile")
	}
}

type testUser struct {
	Mobile string `json:"mobile" mask:"mobile"`
	Email  string `json:"email" mask:"email"`
}

type nestedUser struct {
	Profile testUser `json:"profile"`
}
