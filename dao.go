package authentication

type User interface {
	Username() string
	Authenticate(pass string) (bool, error)
}

type UserDAO interface {
	Get(string) (User, error)
}
