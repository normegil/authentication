package authentication

import (
	"net/http"

	"context"

	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/normegil/resterrors"
	"github.com/pkg/errors"
)

const USERNAME_KEY = "USERNAME"
const HEADER_JWT = "Authentication"
const jwtTokenTimeToLive = 24 * time.Hour

var authenticationError = errors.New("authentication failed")

type Authenticator struct {
	DAO          UserDAO
	ErrorHandler resterrors.Handler
	PrivateKey   *ecdsa.PrivateKey
	PublicKey    *ecdsa.PublicKey
}

func (a Authenticator) Authenticate(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, err := a.AuthenticateRequest(r)
		if nil != err {
			a.ErrorHandler.Handle(w, errors.Wrapf(err, "Could not authenticate request"))
			return
		}

		token, err := a.EmitToken(a.PrivateKey, jwt.StandardClaims{
			Subject:   username,
			ExpiresAt: time.Now().Add(jwtTokenTimeToLive).Unix(),
		})
		if err != nil {
			a.ErrorHandler.Handle(w, errors.Wrapf(err, "Could not emit JWT token"))
			return
		}
		w.Header().Add(HEADER_JWT, "Bearer "+token)

		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), USERNAME_KEY, username)))
	})
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

	token, err := request.ParseFromRequest(r, request.HeaderExtractor{HEADER_JWT}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.PublicKey, nil
	})
	if err != nil {
		return "", errors.Wrapf(err, "Parsing token from %s", HEADER_JWT)
	}

	if token.Valid {
		claims, ok := token.Claims.(jwt.StandardClaims)
		if !ok {
			return "", errors.Wrapf(err, "obtaining standard claims struct from token claims")
		}
		return claims.Subject, nil
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
