package gin_test

import (
	"testing"

	darkgin "github.com/darkit/gin"
	upstream "github.com/gin-gonic/gin"
)

func TestMIMEConstantsStayAlignedWithUpstream(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		local    string
		upstream string
	}{
		{name: "MIMEJSON", local: darkgin.MIMEJSON, upstream: upstream.MIMEJSON},
		{name: "MIMEHTML", local: darkgin.MIMEHTML, upstream: upstream.MIMEHTML},
		{name: "MIMEXML", local: darkgin.MIMEXML, upstream: upstream.MIMEXML},
		{name: "MIMEXML2", local: darkgin.MIMEXML2, upstream: upstream.MIMEXML2},
		{name: "MIMEPlain", local: darkgin.MIMEPlain, upstream: upstream.MIMEPlain},
		{name: "MIMEPOSTForm", local: darkgin.MIMEPOSTForm, upstream: upstream.MIMEPOSTForm},
		{name: "MIMEMultipartPOSTForm", local: darkgin.MIMEMultipartPOSTForm, upstream: upstream.MIMEMultipartPOSTForm},
		{name: "MIMEYAML", local: darkgin.MIMEYAML, upstream: upstream.MIMEYAML},
		{name: "MIMEYAML2", local: darkgin.MIMEYAML2, upstream: upstream.MIMEYAML2},
		{name: "MIMETOML", local: darkgin.MIMETOML, upstream: upstream.MIMETOML},
		{name: "MIMEPROTOBUF", local: darkgin.MIMEPROTOBUF, upstream: upstream.MIMEPROTOBUF},
		{name: "MIMEBSON", local: darkgin.MIMEBSON, upstream: upstream.MIMEBSON},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.local != tc.upstream {
				t.Fatalf("%s mismatch: local=%q upstream=%q", tc.name, tc.local, tc.upstream)
			}
		})
	}
}
