package authentication

import (
	"net/http"

	"context"

	"github.com/normegil/resterrors"
	"github.com/pkg/errors"
)

const USERNAME_KEY = "USERNAME"

var authenticationError = errors.New("authentication failed")

type Authenticator struct {
	DAO          UserDAO
	ErrorHandler resterrors.Handler
}

func (a Authenticator) Authenticate(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, err := a.AuthenticateRequest(r)
		if nil != err {
			a.ErrorHandler.Handle(w, errors.Wrapf(err, "Could not authenticate request"))
		}
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
	return "", errors.New("no authentication info or unsupported authentication method")
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
