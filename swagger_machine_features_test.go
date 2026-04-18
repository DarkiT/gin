package gin_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/darkit/gin"
	"github.com/darkit/gin/pkg/swagger"
)

func TestSwaggerMachineFriendlyFeatures(t *testing.T) {
	e := gin.New(
		gin.EnableSwagger(swagger.SwaggerConfig{
			Title:   "机器友好 API",
			Version: "1.0.0",
		}),
	)

	e.Router().POSTDoc("/jobs", func(c *gin.Context) {
		c.Created(gin.H{"id": "job_1"})
	}).
		Doc("创建任务").
		OperationID("createJob").
		ParamModel("body", "body", "任务创建参数", true, gin.H{}).
		RequestExample(gin.H{"name": "demo-job"}).
		Response(http.StatusCreated, "创建成功", gin.H{}).
		ResponseExamples(http.StatusCreated, map[string]swagger.Example{
			"created": {
				Summary: "创建成功示例",
				Value:   gin.H{"id": "job_1"},
			},
		}).
		DefaultErrors(http.StatusBadRequest, http.StatusUnprocessableEntity, http.StatusInternalServerError)

	req := httptest.NewRequest(http.MethodGet, "/swagger/doc.json", nil)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var spec swagger.OpenAPI
	if err := json.NewDecoder(w.Body).Decode(&spec); err != nil {
		t.Fatalf("decode swagger spec: %v", err)
	}

	pathItem := spec.Paths["/jobs"]
	if pathItem.Post == nil {
		t.Fatalf("expected POST operation on /jobs")
	}
	if pathItem.Post.OperationID != "createJob" {
		t.Fatalf("unexpected operationId: %s", pathItem.Post.OperationID)
	}
	if pathItem.Post.RequestBody == nil {
		t.Fatalf("expected request body")
	}
	requestMedia := pathItem.Post.RequestBody.Content["application/json"]
	if requestMedia.Example == nil {
		t.Fatalf("expected request example")
	}

	createdResp := pathItem.Post.Responses["201"]
	createdMedia := createdResp.Content["application/json"]
	if len(createdMedia.Examples) != 1 {
		t.Fatalf("expected one response example, got %d", len(createdMedia.Examples))
	}

	badRequestResp := pathItem.Post.Responses["400"]
	if _, ok := badRequestResp.Content["application/problem+json"]; !ok {
		t.Fatalf("expected problem+json default error response")
	}
}
