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
)

type AuthResponse struct {
	Code        int    `json:"code"`
	Explanation string `json:"explanation"`
}

//Auth authenticate and authorize the request
func Auth(requiredPermission string, requiredAction int) restful.FilterFunction {
	return func(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
		rawToken := req.HeaderParameter("Authorization")
		splittedToken := strings.Fields(rawToken)

		if len(splittedToken) != 2 {
			responseBodyUnauthenticated := &AuthResponse{
				Code:        UnauthenticatedRequestCode,
				Explanation: UnauthenticatedRequestExplanation,
			}
			_ = resp.WriteHeaderAndJson(
				http.StatusUnauthorized,
				responseBodyUnauthenticated,
				restful.MIME_JSON,
			)
			return
		}

		if splittedToken[0] != BearerTokenType {
			responseBodyUnauthenticated := &AuthResponse{
				Code:        UnauthenticatedRequestCode,
				Explanation: UnauthenticatedRequestExplanation,
			}
			_ = resp.WriteHeaderAndJson(
				http.StatusUnauthorized,
				responseBodyUnauthenticated,
				restful.MIME_JSON,
			)
			return
		}

		responseBodyUnauthenticated := &AuthResponse{
			Code:        UnauthenticatedRequestCode,
			Explanation: UnauthenticatedRequestExplanation,
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

		isExpire := expirationMatcher(claim)
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
	expectedResourceSplits := strings.Split(expectedResource, ":")
	splitLen := len(expectedResourceSplits)

	if splitLen == 2 {
		return publicPermissionMatcher(expectedResourceSplits, expectedAction, claims, req)
	} else if splitLen == 3 && strings.HasPrefix(expectedResource, Admin) {
		return adminPermissionMatcher(expectedResourceSplits, expectedAction, claims, req)
	}

	expectedResourcePrefix := expectedResourceSplits[0]
	permissionClaimMap := claims.Permissions
	return permissionClaimMap[expectedResourcePrefix]&expectedAction > 0

}

func adminPermissionMatcher(expectedResourceSplits []string, expectedAction int, claims *claim.IdentityClaim, req *restful.Request) bool {
	expectedResourceParam := expectedResourceSplits[2]
	permissionClaimMap := claims.Permissions

	expectedResourcePrefix := expectedResourceSplits[1]

	if expectedResourceParam == "*" { // the form will be such *, e.g. user:*
		for k, v := range permissionClaimMap {
			permSplit := strings.Split(k, ":")
			if len(permSplit) != 3 {
				continue
			}

			if permSplit[1] == expectedResourcePrefix && v&expectedAction > 0 {
				return true
			}
		}
		return false
	}

	// else the form will be such {userId}, e.g. user:{userId}
	for k, v := range permissionClaimMap {
		permSplit := strings.Split(k, ":")
		if len(permSplit) != 3 {
			continue
		}

		if permSplit[1] == expectedResourcePrefix {
			strippedPrefix := expectedResourceParam[1 : len(expectedResourceParam)-2]
			if strippedPrefix == UserID {
				userID := req.PathParameter(UserID)
				return claims.UserID == userID && v&expectedAction > 0
			}

			return v&expectedAction > 0
		}
	}
	return false
}

func publicPermissionMatcher(expectedResourceSplits []string, expectedAction int, claims *claim.IdentityClaim, req *restful.Request) bool {
	expectedResourceParam := expectedResourceSplits[1]
	permissionClaimMap := claims.Permissions

	expectedResourcePrefix := expectedResourceSplits[0]

	if expectedResourceParam == "*" { // the form will be such *, e.g. user:*
		for k, v := range permissionClaimMap {
			permSplit := strings.Split(k, ":")
			if len(permSplit) != 2 {
				continue
			}

			if permSplit[0] == expectedResourcePrefix && v&expectedAction > 0 {
				return true
			}
		}
		return false
	}

	// else the form will be such {userId}, e.g. user:{userId}
	for k, v := range permissionClaimMap {
		permSplit := strings.Split(k, ":")
		if len(permSplit) != 2 {
			continue
		}

		if permSplit[0] == expectedResourcePrefix {
			strippedPrefix := expectedResourceParam[1 : len(expectedResourceParam)-1]
			if strippedPrefix == UserID {
				userID := req.PathParameter(UserID)
				return claims.UserID == userID && v&expectedAction > 0
			}

			return v&expectedAction > 0
		}
	}
	return false
}

func expirationMatcher(claims *claim.IdentityClaim) bool {
	now := time.Now().Unix()
	return claims.ExpiresAt <= now
}
