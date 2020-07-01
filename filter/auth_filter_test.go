package filter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/emicklei/go-restful"

	"github.com/stretchr/testify/assert"
)

func TestMatchOneClaim(t *testing.T) {
	auth := NewAuthFilter("testKey")

	claimedResource := []string{"external", "fnb", "tenantA", "kiosk", "123456", "customer"}
	requiredResource := []string{"external", "fnb", "tenantA", "kiosk", "123456", "customer"}
	testResult := auth.matchOneClaim(claimedResource, requiredResource)
	assert.Equal(t, true, testResult)

	claimedResource = []string{"external", "fnb", "tenantA", "kiosk", "123456", "customer"}
	requiredResource = []string{"external", "fnb", "tenantA", "kiosk", "*", "customer"}
	testResult = auth.matchOneClaim(claimedResource, requiredResource)
	assert.Equal(t, true, testResult)

	claimedResource = []string{"external", "fnb", "tenantA", "kiosk", "*", "customer"}
	requiredResource = []string{"external", "fnb", "tenantA", "kiosk", "12345", "customer"}
	testResult = auth.matchOneClaim(claimedResource, requiredResource)
	assert.Equal(t, true, testResult)

	claimedResource = []string{"external", "fnb", "*", "kiosk", "*", "customer"}
	requiredResource = []string{"external", "fnb", "tenantA", "kiosk", "12345", "customer"}
	testResult = auth.matchOneClaim(claimedResource, requiredResource)
	assert.Equal(t, true, testResult)

	claimedResource = []string{"external", "fnb", "tenantA", "kiosk", "*"}
	requiredResource = []string{"external", "fnb", "tenantA", "kiosk", "12345"}
	testResult = auth.matchOneClaim(claimedResource, requiredResource)
	assert.Equal(t, true, testResult)

	claimedResource = []string{"external", "fnb", "tenantA", "kiosk", "123456", "customer"}
	requiredResource = []string{"internal", "fnb", "tenantA", "kiosk", "*", "customer"}
	testResult = auth.matchOneClaim(claimedResource, requiredResource)
	assert.Equal(t, false, testResult)
}

var DummyHandlerResult = ""

func DummyHandler(initialResource string) func(req *restful.Request, resp *restful.Response) {
	return func(req *restful.Request, resp *restful.Response) {
		auth := NewAuthFilter("testKey")
		DummyHandlerResult = auth.replacePlaceholders(initialResource, req)
	}
}

func TestReplacePlaceholder(t *testing.T) {

	initialResource1 := "external:fnb:tenant:{tenant}:menu"
	initialResource2 := "external:fnb:tenant:{tenant}:kiosk:{kioskId}"
	initialResource3 := "external:fnb:tenant:{tenant}:kiosk:{kioskId}"
	initialResource4 := "external:fnb:tenant:{tenant}:kiosk:*"

	ws := new(restful.WebService)
	ws.Consumes(restful.MIME_XML)
	ws.Route(ws.GET("/external/{tenant}").To(DummyHandler(initialResource1)))
	ws.Route(ws.GET("/external/{tenant}/kiosk/{kioskId}/menu").To(DummyHandler(initialResource2)))
	ws.Route(ws.GET("/external/{tenant}/kiosk/{kioskId}/menu/people/{peopleId}").To(DummyHandler(initialResource3)))
	ws.Route(ws.GET("/external/{tenant}/kiosk/{kioskId}").To(DummyHandler(initialResource4)))
	restful.Add(ws)

	bodyReader := strings.NewReader("")
	httpRequest, _ := http.NewRequest("GET", "/external/abctenant", bodyReader)
	httpRequest.Header.Set("Content-Type", restful.MIME_XML)
	httpWriter := httptest.NewRecorder()

	restful.DefaultContainer.ServeHTTP(httpWriter, httpRequest)

	// this is rather stupid approach for test, but gorestful didn't write the interface and I'm too lazy to wrap restful.Request just for test
	expectedResource := "external:fnb:tenant:abctenant:menu"
	assert.Equal(t, expectedResource, DummyHandlerResult, "Should replace placeholder")

	httpRequest, _ = http.NewRequest("GET", "/external/abctenant/kiosk/kioskabc/menu", bodyReader)
	restful.DefaultContainer.ServeHTTP(httpWriter, httpRequest)

	expectedResource = "external:fnb:tenant:abctenant:kiosk:kioskabc"
	assert.Equal(t, expectedResource, DummyHandlerResult, "Should replace placeholder")

	httpRequest, _ = http.NewRequest("GET", "/external/abctenant/kiosk/kioskabc/menu/people/john", bodyReader)
	restful.DefaultContainer.ServeHTTP(httpWriter, httpRequest)

	expectedResource = "external:fnb:tenant:abctenant:kiosk:kioskabc"
	assert.Equal(t, expectedResource, DummyHandlerResult, "Should not append anything")

	httpRequest, _ = http.NewRequest("GET", "/external/abctenant/kiosk/kioskabc", bodyReader)
	restful.DefaultContainer.ServeHTTP(httpWriter, httpRequest)

	expectedResource = "external:fnb:tenant:abctenant:kiosk:*"
	assert.Equal(t, expectedResource, DummyHandlerResult, "Should not change the *")
}

func TestMatchWithClaims(t *testing.T) {
	auth := NewAuthFilter("testKey")

	testClaimedPerm := make(map[string]int)
	testClaimedPerm["internal:hrm:tenant:abctenant:kiosk:*"] = 1
	testClaimedPerm["internal:hrm:tenant:abctenant:menu"] = 3
	testClaimedPerm["external:fnb:tenant:abctenant:discount"] = 15

	requiredResource := "internal:hrm:tenant:*:kiosk:*"
	result := auth.matchWithClaims(requiredResource, 1, testClaimedPerm)
	assert.Equal(t, true, result, "Should match")

	requiredResource = "internal:hrm:tenant:*:menu"
	result = auth.matchWithClaims(requiredResource, 1, testClaimedPerm)
	assert.Equal(t, true, result, "Should match")

	requiredResource = "internal:hrm:tenant:*:menu"
	result = auth.matchWithClaims(requiredResource, 2, testClaimedPerm)
	assert.Equal(t, true, result, "Should match")

	requiredResource = "internal:hrm:tenant:*:menu"
	result = auth.matchWithClaims(requiredResource, 8, testClaimedPerm)
	assert.Equal(t, false, result, "Should not match")

	requiredResource = "internal:fnb:tenant:*:discount"
	result = auth.matchWithClaims(requiredResource, 8, testClaimedPerm)
	assert.Equal(t, false, result, "Should not match")
}
