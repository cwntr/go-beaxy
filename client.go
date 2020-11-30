package go_beaxy

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"

	"modernc.org/mathutil"
)

const (
	// Public REST API
	PublicURL       = "https://services.beaxy.com/api/v2/"
	EndpointSymbols = "symbols"

	//Trading REST API
	TradingURL            = "https://tradingapi.beaxy.com/api/v1/"
	EndpointLoginAttempt  = "login/attempt"
	EndpointLoginConfirm  = "login/confirm"
	EndpointAccounts      = "accounts"
	EndpointOrders        = "orders"
	EndpointOrdersHistory = "orders/history"

	ReqHeaderNonce         = "X-Deltix-Nonce"
	ReqHeaderSessionId     = "X-Deltix-Session-Id"
	ReqHeaderSignature     = "X-Deltix-Signature"
	ReqHeaderOrderId       = "X-Deltix-Order-ID"
	ReqHeaderClientOrderId = "X-Deltix-Client-Order-ID"

	ReqHeaderContentType = "Content-Type"
	ReqHeaderJson        = "application/json"
)

// Client struct holds data how to connect to Beaxy REST API
type Client struct {
	TradingURL string
	PublicURL  string
	HTTPClient *http.Client
	log        *logrus.Logger

	//DebugMode will print logs for debugging authentication and endpoints
	isDebugMode bool

	//Given by Beaxy API Management
	APIKey               string
	APIPrivateKeyContent string

	//Session related
	PrivateKey       *rsa.PrivateKey
	SessionID        string
	SessionChallenge string
	DhBase           string
	DhModulus        string
	DhNumberBytes    []byte
	DhKey            string
	SecretKey        string

	//Ruleset
	Ruleset Rulebook
}

// NewClient will create Client object that can be used to request all possible exchange endpoints
// Mandatory parameter: apiKey and keyContent which are given from Beaxy API Management
func NewClient(apiKey string, keyContent string) *Client {
	c := &Client{}
	c.TradingURL = TradingURL
	c.PublicURL = PublicURL
	c.APIKey = apiKey
	c.log = logrus.New()

	key, err := parsePrivateKey(keyContent)
	if err != nil {
		c.log.Errorf("unable to parse private key, err:%v", err)
		return nil
	}
	c.PrivateKey = key

	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}
	c.HTTPClient = &http.Client{Transport: tr}
	err = c.Auth()
	if err != nil {
		c.log.Errorf("[auth] error while authenticating: %v ", err)
		return nil
	}
	/*
		err = c.WSConnect()
		if err != nil {
			c.log.Errorf("[auth] error while connecting to websocket: %v ", err)
			return nil
		}
	*/

	err = c.SetRulebook()
	return c
}

// EnableDebugMode will enable the debug mode
func (c *Client) EnableDebugMode() {
	c.isDebugMode = true
	c.log.Level = logrus.DebugLevel
}

// Retrieves all symbols limits and maps it into local rulebook for validation purposes
func (c *Client) SetRulebook() error {
	req, err := http.NewRequest("GET", c.GetPublicAPIUrl(EndpointSymbols, url.Values{}), nil)
	if err != nil {
		return err
	}
	req.Header.Add(ReqHeaderContentType, ReqHeaderJson)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	if c.isDebugMode {
		c.log.Debugf("[set-rulebook] response status: %d", resp.StatusCode)
	}
	var resData Rulebook
	err = getJson(resp, &resData)
	if err != nil {
		return err
	}

	c.Ruleset = resData
	return nil
}

// Auth func will execute a 3 step flow by login, confirm and get accounts to check if auth is working
// it will retry as long as the session secret seems to be working fine.
// @TODO: investigate why it doesnt work for every session attempt, fix it and remove that retry loop.
func (c *Client) Auth() error {
	i := 0
	for {
		i++
		c.log.Infof("[auth] iteration: %d", i)
		_, sc, err := c.LoginAttempt()
		if err != nil || sc != 200 {
			return fmt.Errorf("unable to auth with current setup, err: %v, sc: %v", err, sc)
		}

		_, sc, err = c.LoginConfirm()
		if err != nil || sc != 200 {
			return fmt.Errorf("unable to auth with current setup, err: %v, sc: %v", err, sc)
		}
		_, sc, _ = c.GetActiveOrders()
		if sc == 200 {
			c.log.Infof("[auth, get orders] status code: %d, finally authenticated!", sc)
			return nil
		} else {
			c.log.Infof("[auth, get orders] status code: %d, retrying..", sc)
		}
		time.Sleep(time.Second * 1)
	}
	return nil
}

// GetTradingAPIUrl func will concatenate server host(trading) and the endpoint to be requested
func (c *Client) GetTradingAPIUrl(endpoint string, queryParams url.Values) string {
	if len(queryParams) == 0 {
		return fmt.Sprintf("%s%s", c.TradingURL, endpoint)
	}
	return fmt.Sprintf("%s%s?%s", c.TradingURL, endpoint, queryParams.Encode())
}

// GetPublicAPIUrl func will concatenate server host(public) and the endpoint to be requested
func (c *Client) GetPublicAPIUrl(endpoint string, queryParams url.Values) string {
	if len(queryParams) == 0 {
		return fmt.Sprintf("%s%s", c.PublicURL, endpoint)
	}
	return fmt.Sprintf("%s%s?%s", c.PublicURL, endpoint, queryParams.Encode())
}

// LoginAttempt func will start authentication by passing the api-key to get a session challenge and DH base + modulus
// to be used for 2nd request (LoginConfirm)
func (c *Client) LoginAttempt() (*LoginAttemptResponse, int, error) {
	request, err := json.Marshal(LoginAttemptRequest{c.APIKey})
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequest(http.MethodPost, c.GetTradingAPIUrl(EndpointLoginAttempt, url.Values{}), bytes.NewBuffer(request))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Add(ReqHeaderContentType, ReqHeaderJson)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	var resData LoginAttemptResponse
	err = getJson(resp, &resData)
	if err == nil {
		c.SessionID = resData.SessionID
		c.SessionChallenge = resData.Challenge
		c.DhBase = resData.DhBase
		c.DhModulus = resData.DhModulus
		if c.isDebugMode {
			c.log.Debugf("[login attempt response] raw dh base: %v", c.DhBase)
			c.log.Debugf("[login attempt response] raw dh modulus: %v", c.DhModulus)
		}
	}
	return &resData, resp.StatusCode, nil
}

// LoginConfirm will sign the challenge and calculate dh key from dh base and dh mod with random bytes number
func (c *Client) LoginConfirm() (*LoginConfirmResponse, int, error) {
	if c.isDebugMode {
		c.log.Debugf("[login confirm prep request] session raw challenge: %s", c.SessionChallenge)
	}
	privateKey := c.PrivateKey
	h := sha256.New()
	challengeStr, err := base64.StdEncoding.DecodeString(c.SessionChallenge)
	if err != nil {
		return nil, 0, err
	}
	h.Write([]byte(challengeStr))
	d := h.Sum(nil)

	// Sign challenge
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, d)
	if err != nil {
		return nil, 0, err
	}
	encodedSig := base64.StdEncoding.EncodeToString(signature)
	if c.isDebugMode {
		c.log.Debugf("[login confirm prep request] session challenge decoded: %s", challengeStr)
		c.log.Debugf("[login confirm prep request] signature: %v", signature)
		c.log.Debugf("[login confirm prep request] encoded signature: %v", encodedSig)
	}

	dhMod, err := base64ToBigInt(c.DhModulus)
	if err != nil {
		return nil, 0, err
	}

	dhBase, err := base64ToBigInt(c.DhBase)
	if err != nil {
		return nil, 0, err
	}
	bb, err := generateRandomBytes(512 / 8)
	if err != nil {
		return nil, 0, err
	}
	dhNumber := new(big.Int)
	dhNumber.SetBytes(bb)

	if c.isDebugMode {
		c.log.Debugf("[login confirm prep request] dh base in decoded big.Int: %d", dhBase)
		c.log.Debugf("[login confirm prep request] dh mod in decoded big.Int: %d", dhMod)
		c.log.Debugf("[login confirm prep request] dh number in decoded big.Int: %d", dhNumber)
	}
	c.DhNumberBytes = dhNumber.Bytes()

	// Calculate Diffie-Hellman key
	dhKey := mathutil.ModPowBigInt(dhBase, dhNumber, dhMod)
	encodedDhKey := base64.StdEncoding.EncodeToString(dhKey.Bytes())
	if c.isDebugMode {
		c.log.Debugf("[login confirm prep request] dh key in decoded big.Int: %d", dhKey)
		c.log.Debugf("[login confirm prep request] dh key encoded: %s", encodedDhKey)
	}

	request, err := json.Marshal(LoginConfirmRequest{c.SessionID, encodedSig, encodedDhKey})
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequest(http.MethodPost, c.GetTradingAPIUrl(EndpointLoginConfirm, url.Values{}), bytes.NewBuffer(request))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Add(ReqHeaderContentType, ReqHeaderJson)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	var resData LoginConfirmResponse
	err = getJson(resp, &resData)
	c.DhKey = resData.DhKey
	return &resData, resp.StatusCode, err
}

// GetAccounts will return all accounts associated to the api-key
func (c *Client) GetAccounts() (*GetAccountsResponse, int, error) {
	dhMod, err := base64ToBigInt(c.DhModulus)
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequest("GET", c.GetTradingAPIUrl(EndpointAccounts, url.Values{}), nil)
	if err != nil {
		return nil, 0, err
	}

	dhKey, err := base64ToBigInt(c.DhKey)
	if err != nil {
		return nil, 0, err
	}
	if c.isDebugMode {
		c.log.Debugf("[get-accounts prep] stored dh key: %s", c.DhKey)
		c.log.Debugf("[get-accounts prep] dh key: %d", dhKey)
	}

	// Calculate session secret key
	dhNumber := new(big.Int)
	dhNumber.SetBytes(c.DhNumberBytes)
	secretKey := mathutil.ModPowBigInt(dhKey, dhNumber, dhMod)

	// Build payload and request signature
	mac := hmac.New(sha512.New384, secretKey.Bytes())
	nonce := fmt.Sprintf("%d", getNonce())
	payload := fmt.Sprintf("GET/api/v1/%s%s=%s&%s=%s",
		EndpointAccounts,
		ReqHeaderNonce,
		nonce,
		ReqHeaderSessionId,
		c.SessionID,
	)
	mac.Write([]byte(payload))
	hmacSum := mac.Sum(nil)
	rSignature := base64.StdEncoding.EncodeToString(hmacSum)

	if c.isDebugMode {
		c.log.Debugf("[get-accounts prep] secretKey: %d", secretKey)
		c.log.Debugf("[get-accounts prep] payload: %s", payload)
		c.log.Debugf("[get-accounts prep] hmac sum: %s", secretKey)
		c.log.Debugf("[get-accounts prep] signature: %s", rSignature)
	}

	req.Header.Add(ReqHeaderContentType, ReqHeaderJson)
	req.Header.Add(ReqHeaderNonce, nonce)
	req.Header.Add(ReqHeaderSessionId, c.SessionID)
	req.Header.Add(ReqHeaderSignature, rSignature)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if c.isDebugMode {
		c.log.Debugf("[get-accounts] response status: %d", resp.StatusCode)
		if resp.StatusCode != 200 {
			dump, err := httputil.DumpResponse(resp, true)
			if err != nil {
				c.log.Errorf("[get-accounts] err while dumping response, err: %v", err)
			}
			c.log.Debugf("[get-accounts] response body: %s", string(dump))
		}
	}
	var resData GetAccountsResponse
	err = getJson(resp, &resData)
	return &resData, resp.StatusCode, err
}

// PlaceOrder will post a new order
func (c *Client) PlaceOrder(o PostOrder) (*Order, int, error) {
	dhMod, err := base64ToBigInt(c.DhModulus)
	if err != nil {
		return nil, 0, err
	}

	if o.SecurityID == "" || o.Type == "" || o.Side == "" {
		return nil, 0, err
	}
	if o.TimeInForce == "" {
		o.TimeInForce = GTC.S()
	}
	request, err := json.Marshal(o)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequest("POST", c.GetTradingAPIUrl(EndpointOrders, url.Values{}), bytes.NewBuffer(request))
	if err != nil {
		return nil, 0, err
	}

	dhKey, err := base64ToBigInt(c.DhKey)
	if err != nil {
		return nil, 0, err
	}
	if c.isDebugMode {
		c.log.Debugf("[post-orders prep] stored dh key: %s", c.DhKey)
		c.log.Debugf("[post-orders prep] dh key: %d", dhKey)
	}

	// Calculate session secret key
	dhNumber := new(big.Int)
	dhNumber.SetBytes(c.DhNumberBytes)
	secretKey := mathutil.ModPowBigInt(dhKey, dhNumber, dhMod)

	// Build payload and request signature
	mac := hmac.New(sha512.New384, secretKey.Bytes())
	nonce := fmt.Sprintf("%d", getNonce())
	payload := fmt.Sprintf("POST/api/v1/%s%s=%s&%s=%s%s",
		EndpointOrders,
		ReqHeaderNonce,
		nonce,
		ReqHeaderSessionId,
		c.SessionID,
		string(request),
	)
	mac.Write([]byte(payload))
	hmacSum := mac.Sum(nil)
	rSignature := base64.StdEncoding.EncodeToString(hmacSum)

	if c.isDebugMode {
		c.log.Debugf("[post-orders prep] secretKey: %d", secretKey)
		c.log.Debugf("[post-orders prep] payload: %s", payload)
		c.log.Debugf("[post-orders prep] hmac sum: %s", secretKey)
		c.log.Debugf("[post-orders prep] signature: %s", rSignature)
	}

	req.Header.Add(ReqHeaderContentType, ReqHeaderJson)
	req.Header.Add(ReqHeaderNonce, nonce)
	req.Header.Add(ReqHeaderSessionId, c.SessionID)
	req.Header.Add(ReqHeaderSignature, rSignature)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if c.isDebugMode {
		c.log.Debugf("[post-orders] response status: %d", resp.StatusCode)
		dump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			c.log.Errorf("[post-orders] err while dumping response, err: %v", err)
		}
		c.log.Debugf("[post-orders] response body: %s", string(dump))
	}

	var resData Order
	err = getJson(resp, &resData)
	return &resData, resp.StatusCode, err
}

// DeleteOrder will delete an existing order by passing either orderId or clientOrderId
func (c *Client) DeleteOrder(orderId string) error {
	if orderId == "" {
		return fmt.Errorf("[delete-order] validation error")
	}
	//clientOrderId = strings.ToLower(clientOrderId)
	dhMod, err := base64ToBigInt(c.DhModulus)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodDelete, c.GetTradingAPIUrl(EndpointOrders, url.Values{}), nil)
	if err != nil {
		return err
	}

	dhKey, err := base64ToBigInt(c.DhKey)
	if err != nil {
		return err
	}
	if c.isDebugMode {
		c.log.Debugf("[delete-order prep] stored dh key: %s", c.DhKey)
		c.log.Debugf("[delete-order prep] dh key: %d", dhKey)
	}

	// Calculate session secret key
	dhNumber := new(big.Int)
	dhNumber.SetBytes(c.DhNumberBytes)
	secretKey := mathutil.ModPowBigInt(dhKey, dhNumber, dhMod)

	// Build payload and request signature
	mac := hmac.New(sha512.New384, secretKey.Bytes())
	nonce := fmt.Sprintf("%d", getNonce())
	payload := fmt.Sprintf("%s/api/v1/%s%s=%s&%s=%s",
		http.MethodDelete,
		EndpointOrders,
		ReqHeaderNonce,
		nonce,
		ReqHeaderSessionId,
		c.SessionID,
	)
	mac.Write([]byte(payload))
	hmacSum := mac.Sum(nil)
	rSignature := base64.StdEncoding.EncodeToString(hmacSum)

	if c.isDebugMode {
		c.log.Debugf("[delete-order prep] secretKey: %d", secretKey)
		c.log.Debugf("[delete-order prep] payload: %s", payload)
		c.log.Debugf("[delete-order prep] hmac sum: %s", secretKey)
		c.log.Debugf("[delete-order prep] signature: %s", rSignature)
	}

	req.Header.Add(ReqHeaderContentType, ReqHeaderJson)
	req.Header.Add(ReqHeaderOrderId, orderId)
	req.Header.Add(ReqHeaderNonce, nonce)
	req.Header.Add(ReqHeaderSessionId, c.SessionID)
	req.Header.Add(ReqHeaderSignature, rSignature)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	if c.isDebugMode {
		c.log.Debugf("[delete-order] response status: %d", resp.StatusCode)
		dump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			c.log.Errorf("[delete-order] err while dumping response, err: %v", err)
		}
		c.log.Debugf("[delete-order] response body: %s", string(dump))
	}

	if resp.StatusCode > 202 {
		return fmt.Errorf("[delete-order] status code: %d", resp.StatusCode)
	}
	return nil
}

// GetActiveOrders will open orders for every trading pair
func (c *Client) GetActiveOrders() (*GetOrdersResponse, int, error) {
	dhMod, err := base64ToBigInt(c.DhModulus)
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequest("GET", c.GetTradingAPIUrl(EndpointOrders, url.Values{}), nil)
	if err != nil {
		return nil, 0, err
	}

	dhKey, err := base64ToBigInt(c.DhKey)
	if err != nil {
		return nil, 0, err
	}
	if c.isDebugMode {
		c.log.Debugf("[get-orders prep] stored dh key: %s", c.DhKey)
		c.log.Debugf("[get-orders prep] dh key: %d", dhKey)
	}

	// Calculate session secret key
	dhNumber := new(big.Int)
	dhNumber.SetBytes(c.DhNumberBytes)
	secretKey := mathutil.ModPowBigInt(dhKey, dhNumber, dhMod)

	// Build payload and request signature
	mac := hmac.New(sha512.New384, secretKey.Bytes())
	nonce := fmt.Sprintf("%d", getNonce())
	payload := fmt.Sprintf("GET/api/v1/%s%s=%s&%s=%s",
		EndpointOrders,
		ReqHeaderNonce,
		nonce,
		ReqHeaderSessionId,
		c.SessionID,
	)
	mac.Write([]byte(payload))
	hmacSum := mac.Sum(nil)
	rSignature := base64.StdEncoding.EncodeToString(hmacSum)

	if c.isDebugMode {
		c.log.Debugf("[get-orders prep] secretKey: %d", secretKey)
		c.log.Debugf("[get-orders prep] payload: %s", payload)
		c.log.Debugf("[get-orders prep] hmac sum: %s", secretKey)
		c.log.Debugf("[get-orders prep] signature: %s", rSignature)
	}

	req.Header.Add(ReqHeaderContentType, ReqHeaderJson)
	req.Header.Add(ReqHeaderNonce, nonce)
	req.Header.Add(ReqHeaderSessionId, c.SessionID)
	req.Header.Add(ReqHeaderSignature, rSignature)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if c.isDebugMode {
		c.log.Debugf("[get-orders] response status: %d", resp.StatusCode)
		if resp.StatusCode != 200 {
			dump, err := httputil.DumpResponse(resp, true)
			if err != nil {
				c.log.Errorf("[get-orders] err while dumping response, err: %v", err)
			}
			c.log.Debugf("[get-orders] response body: %s", string(dump))
		}
	}
	var resData GetOrdersResponse
	err = getJson(resp, &resData)
	return &resData, resp.StatusCode, nil
}

// GetOrder will return details of a specific order (regardless of its state)
func (c *Client) GetOrder(orderId string) (*GetOrdersResponse, int, error) {
	if orderId == "" {
		return nil, 0, fmt.Errorf("[get-order] unable to get order with empty order-id")
	}
	dhMod, err := base64ToBigInt(c.DhModulus)
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequest("GET", c.GetTradingAPIUrl(EndpointOrders, url.Values{}), nil)
	if err != nil {
		return nil, 0, err
	}

	dhKey, err := base64ToBigInt(c.DhKey)
	if err != nil {
		return nil, 0, err
	}
	if c.isDebugMode {
		c.log.Debugf("[get-order prep] stored dh key: %s", c.DhKey)
		c.log.Debugf("[get-order prep] dh key: %d", dhKey)
	}

	// Calculate session secret key
	dhNumber := new(big.Int)
	dhNumber.SetBytes(c.DhNumberBytes)
	secretKey := mathutil.ModPowBigInt(dhKey, dhNumber, dhMod)

	// Build payload and request signature
	mac := hmac.New(sha512.New384, secretKey.Bytes())
	nonce := fmt.Sprintf("%d", getNonce())
	payload := fmt.Sprintf("GET/api/v1/%s%s=%s&%s=%s",
		EndpointOrders,
		ReqHeaderNonce,
		nonce,
		ReqHeaderSessionId,
		c.SessionID,
	)
	mac.Write([]byte(payload))
	hmacSum := mac.Sum(nil)
	rSignature := base64.StdEncoding.EncodeToString(hmacSum)

	if c.isDebugMode {
		c.log.Debugf("[get-order prep] secretKey: %d", secretKey)
		c.log.Debugf("[get-order prep] payload: %s", payload)
		c.log.Debugf("[get-order prep] hmac sum: %s", secretKey)
		c.log.Debugf("[get-order prep] signature: %s", rSignature)
	}

	req.Header.Add(ReqHeaderContentType, ReqHeaderJson)
	req.Header.Add(ReqHeaderNonce, nonce)
	req.Header.Add(ReqHeaderSessionId, c.SessionID)
	req.Header.Add(ReqHeaderOrderId, orderId)
	req.Header.Add(ReqHeaderSignature, rSignature)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if c.isDebugMode {
		c.log.Debugf("[get-order] response status: %d", resp.StatusCode)
		dump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			c.log.Errorf("[get-order] err while dumping response, err: %v", err)
		}
		c.log.Debugf("[get-order] response body: %s", string(dump))
	}
	var resData GetOrdersResponse
	err = getJson(resp, &resData)
	return &resData, resp.StatusCode, nil
}

// GetOrderHistory will return closed orders from point of startTime and limited by count parameter
func (c *Client) GetOrderHistory(count int, startTime time.Time) (*GetOrdersResponse, int, error) {
	if count == 0 {
		return nil, 0, fmt.Errorf("[get-order-history] unable to get order history without count parameter")
	}
	dhMod, err := base64ToBigInt(c.DhModulus)
	if err != nil {
		return nil, 0, err
	}

	u := url.Values{}
	u.Add("count", fmt.Sprintf("%d", 0))
	//u.Add("startTime", fmt.Sprintf("%d", toTimestampMilliseconds(time.Now().AddDate(0, 0, -7))))
	u.Add("startTime", fmt.Sprintf("%d", 0))
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s%s?%s=%d", c.TradingURL, EndpointOrdersHistory, "startTime", 0), nil)
	if err != nil {
		return nil, 0, err
	}
	dhKey, err := base64ToBigInt(c.DhKey)
	if err != nil {
		return nil, 0, err
	}
	if c.isDebugMode {
		c.log.Debugf("[get-order-history prep] stored dh key: %s", c.DhKey)
		c.log.Debugf("[get-order-history prep] dh key: %d", dhKey)
	}

	// Calculate session secret key
	dhNumber := new(big.Int)
	dhNumber.SetBytes(c.DhNumberBytes)
	secretKey := mathutil.ModPowBigInt(dhKey, dhNumber, dhMod)

	// Build payload and request signature
	mac := hmac.New(sha512.New384, secretKey.Bytes())
	nonce := fmt.Sprintf("%d", getNonce())
	payload := fmt.Sprintf("%s/api/v1/%s?%s=%d%s=%s&%s=%s",
		http.MethodGet,
		EndpointOrdersHistory,
		"startTime",
		0,
		ReqHeaderNonce,
		nonce,
		ReqHeaderSessionId,
		c.SessionID,
	)
	mac.Write([]byte(payload))
	hmacSum := mac.Sum(nil)
	rSignature := base64.StdEncoding.EncodeToString(hmacSum)

	if c.isDebugMode {
		c.log.Debugf("[get-order-history prep] secretKey: %d", secretKey)
		c.log.Debugf("[get-order-history prep] payload: %s", payload)
		c.log.Debugf("[get-order-history prep] hmac sum: %s", secretKey)
		c.log.Debugf("[get-order-history prep] signature: %s", rSignature)
	}

	req.Header.Add(ReqHeaderContentType, ReqHeaderJson)
	req.Header.Add(ReqHeaderNonce, nonce)
	req.Header.Add(ReqHeaderSessionId, c.SessionID)
	req.Header.Add(ReqHeaderSignature, rSignature)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if c.isDebugMode {
		c.log.Debugf("[get-order-history] request-url: %s", req.URL.String())
		c.log.Debugf("[get-order-history] response status: %d", resp.StatusCode)
		dump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			c.log.Errorf("[get-order-history] err while dumping response, err: %v", err)
		}
		c.log.Debugf("[get-order-history] response body: %s", string(dump))
	}

	var resData GetOrdersResponse
	err = getJson(resp, &resData)
	return &resData, resp.StatusCode, nil
}

/*
func (c *Client) WSConnect() error {
	dhMod, err := base64ToBigInt(c.DhModulus)
	if err != nil {
		return err
	}
	dhKey, err := base64ToBigInt(c.DhKey)
	if err != nil {
		return err
	}
	if c.isDebugMode {
		c.log.Debugf("[ws-connect] stored dh key: %s", c.DhKey)
		c.log.Debugf("[ws-connect] dh key: %d", dhKey)
	}

	// Calculate session secret key
	dhNumber := new(big.Int)
	dhNumber.SetBytes(c.DhNumberBytes)
	secretKey := mathutil.ModPowBigInt(dhKey, dhNumber, dhMod)

	// Build payload and request signature
	mac := hmac.New(sha512.New384, secretKey.Bytes())
	nonce :=  getNonce()
	payload := fmt.Sprintf(`CONNECT
%s: %d
%s: %s
`,
		ReqHeaderNonce,
		nonce,
		ReqHeaderSessionId,
		c.SessionID,
	)
	mac.Write([]byte(payload))
	hmacSum := mac.Sum(nil)
	rSignature := base64.StdEncoding.EncodeToString(hmacSum)

	stomp.
	conn, err := stomp.Dial("tcp", "tradingapi.beaxy.com/websocket/v1:wss",
		stomp.ConnOpt.AcceptVersion(stomp.V11),
		stomp.ConnOpt.AcceptVersion(stomp.V12),
		stomp.ConnOpt.Header(ReqHeaderNonce, fmt.Sprintf("%d", getNonce())),
		stomp.ConnOpt.Header(ReqHeaderSignature, rSignature),
		stomp.ConnOpt.Header(ReqHeaderSessionId, c.SessionID))

	if err != nil {
		return err
	}
	c.WSConn = conn
	return nil
}
*/
