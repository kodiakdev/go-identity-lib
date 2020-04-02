package filter

import (
	"net/http"
	"strings"
	"time"

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
	SecretKey                         = "my_secret_key"
	UnauthenticatedRequestCode        = 1002001
	UnauthenticatedRequestExplanation = "Unauthenticated request"
	ForbiddenRequestCode              = 1003001
	ForbiddenRequestExplanation       = "Forbidden request. Check your privilege!"
	JWTPayload                        = "jwtPayload"
	TenantPlaceholder                 = "{tenant}"
	UserPlaceholder                   = "{userId}"
	ResourceSeparator                 = ":"
	StarValue                         = "*"
)

type AuthResponse struct {
	Code        int    `json:"code"`
	Explanation string `json:"explanation"`
}

//Auth authenticate and authorize the request
func Auth(requiredPermission string, requiredAction int) restful.FilterFunction {
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

		jwtKey := []byte(SecretKey)

		claim := &claim.IdentityClaim{}
		tkn, err := jwt.ParseWithClaims(splittedToken[1], claim, func(token *jwt.Token) (interface{}, error) {
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

		isExpire := isExpire(claim)
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

		isAuthorized := permissionMatcher(requiredPermission, requiredAction, claim, req)
		if !isAuthorized {
			_ = resp.WriteHeaderAndJson(
				http.StatusForbidden,
				responseBodyForbidden,
				restful.MIME_JSON,
			)
			return
		}

		req.SetAttribute(JWTPayload, claim)

		chain.ProcessFilter(req, resp)
	}
}

func permissionMatcher(expectedResource string, expectedAction int, claims *claim.IdentityClaim, req *restful.Request) bool {
	tenant := req.PathParameter("tenant")
	userID := req.PathParameter("userId")

	if tenant != "" {
		expectedResource = strings.Replace(expectedResource, TenantPlaceholder, tenant, 1)
	}

	if userID != "" {
		expectedResource = strings.Replace(expectedResource, UserPlaceholder, userID, 1)
	}

	claimedPerms := claims.Permissions
	return matchPermission(expectedResource, expectedAction, claimedPerms)

}

//matchPermission match the permission
//remember that resource format is param1:value1:param2:value2:resource
//for example: tenant:*:user:*:menu or just tenant:{tenant}:menu:*
func matchPermission(requiredResource string, requiredAction int, claimedPerms map[string]int) bool {

	if claimedPerms[requiredResource]&requiredAction > 0 { // requred and granted perfectly match
		return true
	}

	requiredResourceSubs := strings.Split(requiredResource, ResourceSeparator)
	for claimedResource, claimedAction := range claimedPerms {
		claimedResourceSubs := strings.Split(claimedResource, ResourceSeparator)
		if len(claimedResourceSubs) != len(requiredResourceSubs) {
			continue
		}
		if match(claimedResourceSubs, requiredResourceSubs) {
			return requiredAction&claimedAction > 0
		}
	}
	return false
}

func match(claimedResourceSubs, requiredResourceSubs []string) bool {
	for i, requiredResourceSub := range requiredResourceSubs {
		if requiredResourceSub != claimedResourceSubs[i] && claimedResourceSubs[i] != StarValue && requiredResourceSub != StarValue {
			return false
		}
	}
	return true
}

func isExpire(claims *claim.IdentityClaim) bool {
	now := time.Now().Unix()
	return claims.ExpiresAt <= now
}
