package ids

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"howett.net/plist"
	"io"
	"net/http"
	"strings"
)

type authTokenRequest struct {
	Username string `plist:"username"`
	Password string `plist:"password"`
}

type authTokenResponse struct {
	ProfileID *string `plist:"profile-id"`
	AuthToken *string `plist:"auth-token"`

	Status int `plist:"status"`
}

type AuthToken struct {
	ProfileID string
	AuthToken string
}

type AuthToken2FACallbackFunc func() (string, error)

func GenerateAuthToken(username, password string, callback AuthToken2FACallbackFunc) (AuthToken, error) {
	return generateAuthToken(username, password, "", callback, 0)
}

func generateAuthToken(username, password, code string, callback AuthToken2FACallbackFunc, retries int) (AuthToken, error) {
	if retries == 3 {
		return AuthToken{}, errors.New("failed to get token after 3 retries")
	}

	authRes, err := postAuthData(username, strings.TrimSuffix(password+code, "\n"))
	if err != nil {
		return AuthToken{}, err
	}

	switch authRes.Status {
	case 0:
		if authRes.AuthToken == nil || authRes.ProfileID == nil {
			return AuthToken{}, errors.New("missing values from response, but got proper status code")
		}

		return AuthToken{ProfileID: *authRes.ProfileID, AuthToken: *authRes.AuthToken}, nil
	case 5000:
		resCode, err := callback()
		if err != nil {
			return AuthToken{}, err
		}

		retries += 1
		return generateAuthToken(username, password, resCode, callback, retries)
	case 5012:
		retries += 1
		return generateAuthToken(username, password, "", callback, retries)
	}

	return AuthToken{}, errors.New("got an unexpected status code")
}

func postAuthData(username, password string) (authTokenResponse, error) {
	data := authTokenRequest{
		Username: username,
		Password: password,
	}

	buf, err := plist.Marshal(&data, plist.XMLFormat)
	if err != nil {
		return authTokenResponse{}, err
	}

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	res, err := client.Post("https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateUser", "application/x-apple-plist", bytes.NewReader(buf))
	if err != nil {
		return authTokenResponse{}, err
	}

	resBuf := bytes.Buffer{}
	if _, err := io.Copy(&resBuf, res.Body); err != nil {
		fmt.Println(err)
		return authTokenResponse{}, err
	}

	var authRes authTokenResponse
	if _, err := plist.Unmarshal(resBuf.Bytes(), &authRes); err != nil {
		return authTokenResponse{}, err
	}

	return authRes, nil
}
