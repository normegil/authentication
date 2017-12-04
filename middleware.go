package authentication

import (
	"net/http"

	"crypto/ecdsa"
	"fmt"
	"time"

	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/normegil/resterrors"
	"github.com/pkg/errors"
)

const HEADER_JWT = "Authorization"
const jwtTokenTimeToLive = 24 * time.Hour
const jwtHeaderPrefix = "Bearer "

var authenticationError = errors.New("authentication failed")

type Authenticator struct {
	DAO          UserDAO
	ErrorHandler resterrors.Handler
	PrivateKey   *ecdsa.PrivateKey
	PublicKey    *ecdsa.PublicKey
}

type AuthenticationInfo struct {
	Username string
	Token    string
}

func (a Authenticator) Authenticate(r *http.Request) (AuthenticationInfo, error) {
	username, err := a.AuthenticateRequest(r)
	if nil != err {
		return AuthenticationInfo{}, errors.Wrapf(err, "Could not authenticate request")
	}

	token, err := a.EmitToken(a.PrivateKey, jwt.StandardClaims{
		Subject:   username,
		ExpiresAt: time.Now().Add(jwtTokenTimeToLive).Unix(),
	})
	if err != nil {
		return AuthenticationInfo{}, errors.Wrapf(err, "Could not emit JWT token")
	}
	return AuthenticationInfo{username, token}, nil
}

func (a Authenticator) AuthenticateRequest(r *http.Request) (string, error) {
	username, password, ok := r.BasicAuth()
	if ok {
		authenticated, err := a.basicAuth(username, password)
		if err != nil {
			return "", errors.Wrapf(err, "basic authentication failed")
		}
		if authenticated {
			return username, nil
		}
		return "", authenticationError
	}

	jwtHeader := r.Header.Get(HEADER_JWT)
	if "" != jwtHeader && strings.HasPrefix(jwtHeader, jwtHeaderPrefix) {
		splittedHeader := strings.SplitAfter(jwtHeader, jwtHeaderPrefix)
		token, err := jwt.Parse(splittedHeader[1], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return a.PublicKey, nil
		})
		if err != nil {
			return "", errors.Wrapf(err, "parsing token from '%s' header", HEADER_JWT)
		}

		if token.Valid {
			claims, ok := token.Claims.(jwt.StandardClaims)
			if !ok {
				return "", errors.Wrapf(err, "obtaining standard claims struct from token claims")
			}
			return claims.Subject, nil
		}
	}

	return "", errors.New("no authentication info or unsupported authentication method")
}

func (a Authenticator) EmitToken(key *ecdsa.PrivateKey, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES512, claims)
	return token.SignedString(key)
}

func (a Authenticator) basicAuth(username, password string) (bool, error) {
	user, err := a.DAO.Get(username)
	if err != nil {
		return false, errors.Wrapf(err, "loading %s", username)
	}
	authenticated, err := user.Authenticate(password)
	if err != nil {
		return false, errors.Wrapf(err, "authenticate user %s", user.Username())
	}
	return authenticated, nil
}

func IsNotAuthenticatedError(err error) bool {
	return err == authenticationError
}
