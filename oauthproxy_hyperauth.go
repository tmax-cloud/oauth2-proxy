package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"golang.org/x/oauth2"
)

//func (p *OAuthProxy) getIss()

func (p *OAuthProxy) HyperauthGroupList(rw http.ResponseWriter, req *http.Request) {
	session, err := p.getAuthenticatedSession(rw, req)
	if err != nil {
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if session.IsExpired() {
		err := p.ClearSessionCookie(rw, req)
		if err != nil {
			logger.Errorf("Error clearing session cookie", err)
			p.ErrorPage(rw, req, http.StatusInternalServerError, "clear sessions cookie failed")
			return
		}
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	//if session.IsExpired() {
	//	rw.Header().Set("Content-Type", applicationJSON)
	//	rw.WriteHeader(http.StatusUnauthorized)
	//	json.NewEncoder(rw).Encode(map[string]string{
	//		"message": "Token is Expired",
	//	})
	//	return
	//}

	// get iss
	tokenByteArr, err := jwt.DecodeSegment(strings.Split(session.AccessToken, ".")[1])
	if err != nil {
		logger.Errorf("Failed to get iss")
	}
	var decodedTokenMap map[string]interface{}
	json.Unmarshal(tokenByteArr, &decodedTokenMap)
	issuer := decodedTokenMap["iss"].(string)

	hyperauthUrl := issuer + hyperauthGroupListPath
	newReq, _ := http.NewRequest(http.MethodGet, hyperauthUrl, nil)
	// Set Access Token
	newReq.Header.Set("Authorization", "Bearer "+session.AccessToken)
	// Copy query parameters from req
	values := req.URL.Query()
	newReq.URL.RawQuery = values.Encode()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	hyperauthResponse, err := client.Do(newReq)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		logger.Errorf("Internal Server Error while getting Group ListGet from %s", hyperauthUrl)
		json.NewEncoder(rw).Encode("Internal Server Error while getting Group ListGet from " + hyperauthUrl)
		return
	}

	if hyperauthResponse.StatusCode != 200 {
		rw.Header().Set("Content-Type", applicationJSON)
		rw.WriteHeader(http.StatusUnauthorized)
		body, _ := ioutil.ReadAll(hyperauthResponse.Body)
		hyperauthResponse.Body.Close()
		json.NewEncoder(rw).Encode(map[string]string{
			"hyperauth_url": hyperauthUrl,
			"message":       string(body),
		})
		return
	}

	rw.Header().Add("Content-Type", applicationJSON)
	rw.WriteHeader(hyperauthResponse.StatusCode)

	var groupList interface{}
	json.NewDecoder(hyperauthResponse.Body).Decode(&groupList)
	logger.Println(groupList)
	json.NewEncoder(rw).Encode(groupList)
}

func (p *OAuthProxy) HyperauthUserList(rw http.ResponseWriter, req *http.Request) {
	session, err := p.getAuthenticatedSession(rw, req)
	if err != nil {
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if session.IsExpired() {
		err := p.ClearSessionCookie(rw, req)
		if err != nil {
			logger.Errorf("Error clearing session cookie", err)
			p.ErrorPage(rw, req, http.StatusInternalServerError, "clear sessions cookie failed")
			return
		}
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	//if session.IsExpired() {
	//	rw.Header().Set("Content-Type", applicationJSON)
	//	rw.WriteHeader(http.StatusUnauthorized)
	//	json.NewEncoder(rw).Encode(map[string]string{
	//		"message": "Token is Expired",
	//	})
	//	return
	//}

	// get iss
	tokenByteArr, err := jwt.DecodeSegment(strings.Split(session.AccessToken, ".")[1])
	if err != nil {
		logger.Errorf("Unable to decode jwt token segment. %v", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	var decodedTokenMap map[string]interface{}
	json.Unmarshal(tokenByteArr, &decodedTokenMap)
	issuer := decodedTokenMap["iss"].(string)

	//Get UserList from hyperauth (using iss)
	hyperauthUrl := issuer + hyperauthUserListPath
	newReq, _ := http.NewRequest(http.MethodGet, hyperauthUrl, nil)
	newReq.Header.Set("Authorization", "Bearer "+session.AccessToken)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	hyperauthResponse, err := client.Do(newReq)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		logger.Errorf("Internal Server Error while getting User ListGet from %s", hyperauthUrl)
		json.NewEncoder(rw).Encode("Internal Server Error while getting User ListGet from " + hyperauthUrl)
		return
	}

	if hyperauthResponse.StatusCode != 200 {
		rw.Header().Add("Content-Type", applicationJSON)
		rw.WriteHeader(http.StatusUnauthorized)
		body, _ := ioutil.ReadAll(hyperauthResponse.Body)
		hyperauthResponse.Body.Close()
		json.NewEncoder(rw).Encode(map[string]string{
			"hyperauth_url": hyperauthUrl,
			"message":       string(body),
		})
		return
	}

	rw.Header().Set("Content-Type", applicationJSON)
	rw.WriteHeader(hyperauthResponse.StatusCode)
	var userList interface{}
	json.NewDecoder(hyperauthResponse.Body).Decode(&userList)
	logger.Println(userList)
	json.NewEncoder(rw).Encode(userList)
}

func (p *OAuthProxy) TokenInfo(rw http.ResponseWriter, req *http.Request) {
	session, err := p.getAuthenticatedSession(rw, req)
	if err != nil {
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if session.IsExpired() {
		err := p.ClearSessionCookie(rw, req)
		if err != nil {
			logger.Errorf("Error clearing session cookie", err)
			p.ErrorPage(rw, req, http.StatusInternalServerError, "clear sessions cookie failed")
			return
		}
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// get playload from accesstoken
	tokenByteArr, err := jwt.DecodeSegment(strings.Split(session.AccessToken, ".")[1])
	if err != nil {
		logger.Errorf("Failed to get access token")
	}
	var decodedTokenMap map[string]interface{}
	json.Unmarshal(tokenByteArr, &decodedTokenMap)

	// [ims][300246] username must equla 'preferred_username', not 'email'
	// because we do not use email for hypercloud
	// decodedTokenMap["email"] = decodedTokenMap["preferred_username"]
	var email string
	if decodedTokenMap["email"] == nil {
		email = ""
	} else {
		email = decodedTokenMap["email"].(string)
	}

	tokenInfo := struct {
		Iss               string        `json:"iss"`
		Exp               float64       `json:"exp"`
		PreferredUsername string        `json:"preferred_username"`
		Email             string        `json:"email"`
		Group             []interface{} `json:"group"`
	}{
		Iss:               decodedTokenMap["iss"].(string),
		Exp:               decodedTokenMap["exp"].(float64),
		PreferredUsername: decodedTokenMap["preferred_username"].(string),
		Email:             email,
		Group:             decodedTokenMap["group"].([]interface{}),
	}

	//CookieSessionInfo := struct {
	//	//IsExpired   bool                   `json:"isExpired"`
	//	//SessionInfo *sessions.SessionState `json:"sessionInfo"`
	//	TokenInfo map[string]interface{} `json:"tokenInfo"`
	//}{
	//	//IsExpired:   session.IsExpired(),
	//	//SessionInfo: session,
	//	TokenInfo: decodedTokenMap,
	//}
	rw.Header().Set("Content-Type", applicationJSON)
	rw.WriteHeader(http.StatusOK)
	//json.NewEncoder(rw).Encode(CookieSessionInfo)
	json.NewEncoder(rw).Encode(tokenInfo)
}

func (p *OAuthProxy) TauthOnly(rw http.ResponseWriter, req *http.Request) {
	session, err := p.getAuthenticatedSession(rw, req)

	if err != nil {
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	// get iss
	tokenByteArr, err := jwt.DecodeSegment(strings.Split(session.AccessToken, ".")[1])
	if err != nil {
		logger.Errorf("Unable to decode jwt token segment. %v", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	var decodedTokenMap map[string]interface{}
	json.Unmarshal(tokenByteArr, &decodedTokenMap)
	issuer := decodedTokenMap["iss"].(string)
	//redirect := issuer + "/protocol/openid-connect/logout?redirect_uri=" + req.URL.Scheme + "%3A%2F%2F" + req.URL.Host + ":" + req.URL.Port() + "/oauth2/sign_in"
	redirect := issuer + "/protocol/openid-connect/logout"
	//redirect := issuer + "/protocol/openid-connect/logout?redirect_uri=" + "http" + "%3A%2F%2F" + "192.168.8.112:4180" + "/oauth2/sign_in"

	if session.IsExpired() {
		err := p.ClearSessionCookie(rw, req)
		if err != nil {
			logger.Errorf("Error clearing session cookie", err)
			p.ErrorPage(rw, req, http.StatusInternalServerError, "clear sessions cookie failed")
			return
		}
		http.Redirect(rw, req, redirect, http.StatusFound)
		//http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	//if session.IsExpired() {
	//	rw.Header().Set("Content-Type", applicationJSON)
	//	rw.WriteHeader(http.StatusUnauthorized)
	//	json.NewEncoder(rw).Encode(map[string]string{
	//		"message": "Token is Expired",
	//	})
	//	return
	//}
	// Unauthorized cases need to return 403 to prevent infinite redirects with
	// subrequest architectures
	if !authOnlyAuthorize(req, session) {
		http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// we are authenticated
	p.addHeadersForProxying(rw, session)
	p.headersChain.Then(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusAccepted)
	})).ServeHTTP(rw, req)
}

//func (p *OAuthProxy) HyperauthSignOut(rw http.ResponseWriter, req *http.Request) {
//	const hyperauthSignOutPath = "/protocol/openid-connect/logout"
//	session, err := p.getAuthenticatedSession(rw, req)
//	if err != nil {
//		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
//		return
//	}
//	tokenByteArr, err := jwt.DecodeSegment(strings.Split(session.AccessToken, ".")[1])
//	var decodedTokenMap map[string]interface{}
//	json.Unmarshal(tokenByteArr, &decodedTokenMap)
//	issuer := decodedTokenMap["iss"].(string)
//
//	//redirectUri, err := p.appDirector.GetRedirect(req)
//	//baseUrl, err := url.Parse(redirectUri)
//	//if err != nil {
//	//	logger.Errorf("%v", err)
//	//}
//
//	redirect := issuer + hyperauthSignOutPath + "?redirect_uri=" + req.URL.Scheme + "%3A%2F%2F" + req.URL.Host + ":" + req.URL.Port() + "/oauth2/sign_in"
//	logger.Println(redirect)
//
//	err = p.ClearSessionCookie(rw, req)
//	if err != nil {
//		logger.Errorf("Error clearing session cookie: %v", err)
//		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
//		return
//	}
//	http.Redirect(rw, req, redirect, http.StatusFound)
//
//}

func (p *OAuthProxy) Token(rw http.ResponseWriter, req *http.Request) {
	session, err := p.getAuthenticatedSession(rw, req)
	if err != nil {
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	//tokenByteArr, err := jwt.DecodeSegment(strings.Split(session.AccessToken, ".")[1])
	//if err != nil {
	//	logger.Errorf("Unable to decode jwt token segment. %v", err)
	//	rw.WriteHeader(http.StatusInternalServerError)
	//	return
	//}
	//var decodedTokenMap map[string]interface{}
	//json.Unmarshal(tokenByteArr, &decodedTokenMap)
	//issuer := decodedTokenMap["iss"].(string)
	//hyperauthUrl := issuer + "/protocol/openid-connect/token"
	//providerInfo := p.provider.Data()
	//data := url.Values{}
	//data.Set("client_id", providerInfo.ClientID)
	//data.Set("client_secret", providerInfo.ClientSecret)
	//data.Set("refresh_token", session.RefreshToken)
	//data.Set("grant_type", "refresh_token")
	//
	////logger.Println("check providerInfo   ", providerInfo)
	////refreshBody := map[string]string{
	////	"client_id":     providerInfo.ClientID,
	////	"client_secret": providerInfo.ClientSecret,
	////	"refresh_token": session.RefreshToken,
	////	"grant_type":    "refresh_token",
	////}
	////body, _ := json.Marshal(refreshBody)
	////buff := bytes.NewBuffer(body)
	////newReq, err := http.NewRequest(http.MethodPost, hyperauthUrl, buff)
	//newReq, err := http.NewRequest(http.MethodPost, hyperauthUrl, strings.NewReader(data.Encode()))
	//if err != nil {
	//	logger.Errorf("Error clearing session cookie", err)
	//	p.ErrorPage(rw, req, http.StatusInternalServerError, "failed to get token refresh")
	//}
	//newReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	//client := &http.Client{
	//	Transport: &http.Transport{
	//		TLSClientConfig: &tls.Config{
	//			InsecureSkipVerify: true,
	//		},
	//	},
	//}
	//response, err := client.Do(newReq)
	//if err != nil {
	//	logger.Errorf("Error clearing session cookie", err)
	//	p.ErrorPage(rw, req, http.StatusInternalServerError, "failed to get token refresh")
	//}
	//var tokenInfo map[string]interface{}
	//logger.Println("check response body  ", response.Status)
	//err = json.NewDecoder(response.Body).Decode(&tokenInfo)
	//if err != nil {
	//	logger.Println(err)
	//}
	//logger.Println("check token body  ", tokenInfo)
	//err = p.ClearSessionCookie(rw, req)
	//if err != nil {
	//	logger.Errorf("Error clearing session cookie", err)
	//	p.ErrorPage(rw, req, http.StatusInternalServerError, "clear sessions cookie failed")
	//	return
	//}
	//
	//user := "test@tmax.co.kr"
	////newSession := &sessions.SessionState{User: user, Groups: p.basicAuthGroups}
	//newSession := &sessions.SessionState{
	//	CreatedAt:         nil,
	//	ExpiresOn:         nil,
	//	AccessToken:       tokenInfo["access_token"].(string),
	//	IDToken:           tokenInfo["id_token"].(string),
	//	RefreshToken:      tokenInfo["refresh_token"].(string),
	//	Nonce:             nil,
	//	Email:             "",
	//	User:              user,
	//	Groups:            nil,
	//	PreferredUsername: "",
	//}
	//err = p.SaveSession(rw, req, newSession)
	//if err != nil {
	//	logger.Printf("Error saving session: %v", err)
	//	p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
	//	return
	//}
	//rw.Header().Set("Content-Type", applicationJSON)
	//rw.WriteHeader(http.StatusOK)
	//
	//json.NewEncoder(rw).Encode(newSession)

	//p.provider.RefreshSession(context.Background(), session)
	err = p.refreshToken(context.Background(), session)
	if err != nil {
		logger.Errorf("Unable to decode jwt token segment. %v", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	err = p.ClearSessionCookie(rw, req)
	if err != nil {
		logger.Errorf("Error clearing session cookie", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, "clear sessions cookie failed")
		return
	}
	err = p.SaveSession(rw, req, session)
	if err != nil {
		logger.Printf("Error saving session: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	rw.Header().Set("Content-Type", applicationJSON)
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("{}"))
	//json.NewEncoder(rw).Encode(nil)

}

func (p *OAuthProxy) refreshToken(ctx context.Context, s *sessions.SessionState) error {
	//clientSecret, err := p.provider.(*providers.OIDCProvider).GetClientSecret()
	//if err != nil {
	//	return err
	//}
	providerInfo := p.provider.Data()

	c := oauth2.Config{
		ClientID: providerInfo.ClientID,
		//ClientSecret: clientSecret,
		ClientSecret: providerInfo.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: providerInfo.RedeemURL.String(),
		},
	}
	t := &oauth2.Token{
		RefreshToken: s.RefreshToken,
		Expiry:       time.Now().Add(-time.Hour),
	}

	token, err := c.TokenSource(ctx, t).Token()
	if err != nil {
		return fmt.Errorf("failed to get token: %v", err)
	}

	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
	s.IDToken = getIDToken(token)

	s.CreatedAtNow()
	s.SetExpiresOn(token.Expiry)

	return nil
}

// getIDToken extracts an IDToken stored in the `Extra` fields of an
// oauth2.Token
func getIDToken(token *oauth2.Token) string {
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return ""
	}
	return idToken
}
