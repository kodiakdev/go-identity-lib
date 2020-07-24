package filter

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/dgrijalva/jwt-go"
	"github.com/emicklei/go-restful"
	"github.com/kodiakdev/go-identity-lib/claim"
	"github.com/sirupsen/logrus"
)

const (
	HeaderParameterAuthorization      = "Authorization"
	Admin                             = "admin"
	BasicTokenType                    = "Basic"
	BearerTokenType                   = "Bearer"
	UserID                            = "userId"
	ClientID                          = "clientId"
	ClientSecret                      = "clientSecret"
	UnauthenticatedRequestCode        = 1002001
	UnauthenticatedRequestExplanation = "Unauthenticated request"
	ForbiddenRequestCode              = 1003001
	ForbiddenRequestExplanation       = "Forbidden request. Check your privilege!"
	TenantPlaceholder                 = "{tenant}"
	UserPlaceholder                   = "{userId}"
	ResourceSeparator                 = ":"
	StarValue                         = "*"
)

//AuthResponse auth response model
type AuthResponse struct {
	Code        int    `json:"code"`
	Explanation string `json:"explanation"`
}

//IAuthFilter contract for auth filter
type IAuthFilter interface {
	Auth(requiredPermission string, requiredAction int) restful.FilterFunction
	BasicAuth() restful.FilterFunction
}

//AuthFilter auth filter
type AuthFilter struct {
	secretKey string
}

//NewAuthFilter auth filter constructor
func NewAuthFilter(secretKey string) *AuthFilter {
	return &AuthFilter{
		secretKey: secretKey,
	}
}

//Auth authenticate and authorize the request
func (auth *AuthFilter) Auth(requiredPermission string, requiredAction int) restful.FilterFunction {
	return func(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
		rawToken := req.HeaderParameter(HeaderParameterAuthorization)
		splittedToken := strings.Fields(rawToken)

		responseBodyUnauthenticated := &AuthResponse{
			Code:        UnauthenticatedRequestCode,
			Explanation: UnauthenticatedRequestExplanation,
		}

		if len(splittedToken) != 2 {
			_ = resp.WriteHeaderAndJson(
				http.StatusUnauthorized,
				responseBodyUnauthenticated,
				restful.MIME_JSON,
			)
			return
		}

		if splittedToken[0] != BearerTokenType {
			_ = resp.WriteHeaderAndJson(
				http.StatusUnauthorized,
				responseBodyUnauthenticated,
				restful.MIME_JSON,
			)
			return
		}

		jwtKey := []byte(auth.secretKey)

		claimObj := &claim.IdentityClaim{}
		tkn, err := jwt.ParseWithClaims(splittedToken[1], claimObj, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !tkn.Valid {
			logrus.Errorf("Failed to parse claim. TokenValid? %v Error: %s", tkn.Valid, err)
			_ = resp.WriteHeaderAndJson(
				http.StatusUnauthorized,
				responseBodyUnauthenticated,
				restful.MIME_JSON,
			)
			return
		}

		isExpire := auth.isExpire(claimObj)
		if isExpire {
			_ = resp.WriteHeaderAndJson(
				http.StatusUnauthorized,
				responseBodyUnauthenticated,
				restful.MIME_JSON,
			)
			return
		}

		responseBodyForbidden := &AuthResponse{
			Code:        ForbiddenRequestCode,
			Explanation: ForbiddenRequestExplanation,
		}

		requiredPermissionPlaceholderReplaced := auth.replacePlaceholders(requiredPermission, req)
		claimedPerms := claimObj.Permissions
		isAuthorized := auth.matchWithClaims(requiredPermissionPlaceholderReplaced, requiredAction, claimedPerms)
		if !isAuthorized {
			_ = resp.WriteHeaderAndJson(
				http.StatusForbidden,
				responseBodyForbidden,
				restful.MIME_JSON,
			)
			return
		}

		req.SetAttribute(claim.JWTPayload, claimObj)
		req.SetAttribute(claim.RequesterUserID, claimObj.UserID)

		chain.ProcessFilter(req, resp)
	}
}

//replacePlaceholders replace the placeholder from expected resource with one from request path param
//for example: assuming the req.PathParameter(tenant) return 12345
//the resource external:fnb:tenant:{tenant}:menu will become external:fnb:tenant:123456:menu
func (auth *AuthFilter) replacePlaceholders(expectedResource string, req *restful.Request) string {
	newResource := ""
	splittedRes := strings.Split(expectedResource, ResourceSeparator)
	for _, res := range splittedRes {
		if strings.HasPrefix(res, "{") && strings.HasSuffix(res, "}") {
			trimmed := strings.TrimFunc(res, func(r rune) bool {
				return !unicode.IsLetter(r)
			})
			pathParam := req.PathParameter(trimmed)
			if pathParam != "" {
				res = pathParam
			}
		}
		newResource += res + ResourceSeparator
	}
	finalTrim := strings.Trim(newResource, ResourceSeparator)
	return finalTrim
}

//matchWithClaims match the permission
//remember that resource format is visibility:servicename:param1:value1:param2:value2
//for example: internal:fnb:tenant:*:user:*:menu or just tenant:{tenant}:menu:*
func (auth *AuthFilter) matchWithClaims(requiredResource string, requiredAction int, claimedPerms map[string]int) bool {

	if claimedPerms[requiredResource]&requiredAction > 0 { // required and granted perfectly match
		return true
	}

	requiredResourceSubs := strings.Split(requiredResource, ResourceSeparator)
	for claimedResource, claimedAction := range claimedPerms {
		claimedResourceSubs := strings.Split(claimedResource, ResourceSeparator)
		if len(claimedResourceSubs) != len(requiredResourceSubs) {
			continue
		}
		if auth.matchOneClaim(claimedResourceSubs, requiredResourceSubs) {
			return requiredAction&claimedAction > 0
		}
	}
	return false
}

func (auth *AuthFilter) matchOneClaim(claimedResourceSubs, requiredResourceSubs []string) bool {
	for i, requiredResourceSub := range requiredResourceSubs {
		if requiredResourceSub != claimedResourceSubs[i] && claimedResourceSubs[i] != StarValue && requiredResourceSub != StarValue {
			return false
		}
	}
	return true
}

func (auth *AuthFilter) isExpire(claims *claim.IdentityClaim) bool {
	now := time.Now().Unix()
	return claims.ExpiresAt <= now
}

//BasicAuth perform parse and validation for basic auth, and put credential to request attribute
//note that you still needs to validate the credential against what you have in DB. This function does not do that for you.
func (auth *AuthFilter) BasicAuth() restful.FilterFunction {
	return func(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
		rawToken := req.HeaderParameter(HeaderParameterAuthorization)
		splittedToken := strings.Fields(rawToken)

		responseBodyUnauthenticated := &AuthResponse{
			Code:        UnauthenticatedRequestCode,
			Explanation: UnauthenticatedRequestExplanation,
		}

		if len(splittedToken) != 2 {
			_ = resp.WriteHeaderAndJson(
				http.StatusUnauthorized,
				responseBodyUnauthenticated,
				restful.MIME_JSON,
			)
			return
		}

		if splittedToken[0] != BasicTokenType {
			_ = resp.WriteHeaderAndJson(
				http.StatusUnauthorized,
				responseBodyUnauthenticated,
				restful.MIME_JSON,
			)
			return
		}

		contentBytes, err := base64.StdEncoding.DecodeString(splittedToken[1])
		if err != nil {
			logrus.Errorf("Failed to parse the basic auth. Error: %v", err)
			_ = resp.WriteHeaderAndJson(
				http.StatusUnauthorized,
				responseBodyUnauthenticated,
				restful.MIME_JSON,
			)
			return
		}

		content := string(contentBytes)
		contents := strings.Split(content, ":")

		if len(contents) < 1 || len(contents) > 2 {
			_ = resp.WriteHeaderAndJson(
				http.StatusUnauthorized,
				responseBodyUnauthenticated,
				restful.MIME_JSON,
			)
			return
		}

		clientID := contents[0]
		clientSecret := contents[1]
		req.SetAttribute(ClientID, clientID)
		req.SetAttribute(ClientSecret, clientSecret)

		chain.ProcessFilter(req, resp)
	}
}
