package mask

import (
	"fmt"
	"testing"
)

type benchUser struct {
	Mobile  string `mask:"mobile"`
	Email   string `mask:"email"`
	IDCard  string `mask:"idcard"`
	Name    string `mask:"name"`
	Address string `mask:"address"`
}

type benchWrapper struct {
	Profile benchUser            `mask:""`
	Friends []benchUser          `mask:""`
	Meta    map[string]benchUser `mask:""`
	Note    string
}

func BenchmarkMaskValue_LargeStructSlice(b *testing.B) {
	const size = 2000
	users := make([]benchWrapper, 0, size)
	for i := 0; i < size; i++ {
		user := benchUser{
			Mobile:  fmt.Sprintf("138%08d", i),
			Email:   fmt.Sprintf("user%04d@example.com", i),
			IDCard:  fmt.Sprintf("11010519491231%04d", i%10000),
			Name:    fmt.Sprintf("User%04d", i),
			Address: "No.1 Example Street",
		}
		users = append(users, benchWrapper{
			Profile: user,
			Friends: []benchUser{user, user, user},
			Meta:    map[string]benchUser{"self": user},
			Note:    "benchmark",
		})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MaskValue(users)
	}
}
