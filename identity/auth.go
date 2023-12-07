package identity

type Authenticator struct {
}

func (a *Authenticator) Authenticator(username, password string) error {
	return nil
}
