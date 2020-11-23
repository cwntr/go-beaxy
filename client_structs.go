package go_beaxy

const (
	New              OrderStatus = "new"
	Rejected         OrderStatus = "rejected"
	Canceled         OrderStatus = "canceled"
	Replaced         OrderStatus = "replaced"
	PartiallyFilled  OrderStatus = "partially_filled"
	CompletelyFilled OrderStatus = "completely_filled"
	Expired          OrderStatus = "expired"
	PendingNew       OrderStatus = "pending_new"
	PendingCancel    OrderStatus = "pending_cancel"
	PendingReplace   OrderStatus = "pending_replace"
	Suspended        OrderStatus = "suspended"

	Buy  OrderSide = "buy"
	Sell OrderSide = "sell"

	GTC              OrderTimeInForce = "gtc"
	GTD              OrderTimeInForce = "gtd"
	IOC              OrderTimeInForce = "ioc"
	FOK              OrderTimeInForce = "fok"
	DAY              OrderTimeInForce = "day"
	AtTheOpening     OrderTimeInForce = "at_the_opening"
	AtTheClose       OrderTimeInForce = "at_the_close"
	GoodTillCrossing OrderTimeInForce = "good_till_crossing"

	SymbolXSNBTC = "XSNBTC"
	SymbolLTCBTC = "LTCBTC"
)

type LoginAttemptRequest struct {
	APIKeyID string `json:"api_key_id"`
}

type LoginAttemptResponse struct {
	SessionID string `json:"session_id"`
	Challenge string `json:"challenge"`
	DhBase    string `json:"dh_base"`
	DhModulus string `json:"dh_modulus"`
	TTL       int    `json:"ttl"`
}

type LoginConfirmRequest struct {
	SessionID string `json:"session_id"`
	Signature string `json:"signature"`
	DhKey     string `json:"dh_key"`
}

type LoginConfirmResponse struct {
	DhKey            string `json:"dh_key"`
	KeepaliveTimeout int64  `json:"keepalive_timeout"`
}

type GetAccountsResponse []Account
type Account struct {
	Status                string      `json:"status"`
	Balance               string      `json:"balance"`
	MeasurementCurrencyID interface{} `json:"measurement_currency_id"`
	AvailableForTrading   string      `json:"available_for_trading"`
	EnterAveragePrice     interface{} `json:"enter_average_price"`
	CurrentPrice          interface{} `json:"current_price"`
	UnrealizedPnl         interface{} `json:"unrealized_pnl"`
	RealizedPnl           interface{} `json:"realized_pnl"`
	CurrencyID            string      `json:"currency_id"`
	TotalStatistics       []struct {
		Total          string `json:"total"`
		TotalThisDay   string `json:"total_this_day"`
		TotalThisWeek  string `json:"total_this_week"`
		TotalThisMonth string `json:"total_this_month"`
		Type           string `json:"type"`
	} `json:"total_statistics"`
	AvailableForWithdrawal string      `json:"available_for_withdrawal"`
	ID                     string      `json:"id"`
	Properties             interface{} `json:"properties"`
}

type GetOrdersResponse []Order
type Order struct {
	ClientOrderID      string `json:"client_order_id"`
	SecurityID         string `json:"security_id"`
	Type               string `json:"type"`
	Side               string `json:"side"`
	Quantity           string `json:"quantity"`
	TimeInForce        string `json:"time_in_force"`
	Price              string `json:"price"`
	Leverage           string `json:"leverage"`
	ExpireTime         int64  `json:"expire_time"`
	SubmissionTime     int64  `json:"submission_time"`
	Destination        string `json:"destination"`
	Source             string `json:"source"`
	Currency           string `json:"currency"`
	Text               string `json:"text"`
	ID                 string `json:"id"`
	Status             string `json:"status"`
	CumulativeQuantity string `json:"cumulative_quantity"`
	RemainingQuantity  string `json:"remaining_quantity"`
	AveragePrice       string `json:"average_price"`
	ReceiptTime        string `json:"receipt_time"`
	CloseTime          string `json:"close_time"`
}

type PostOrder struct {
	SecurityID  string `json:"security_id"` //required
	Type        string `json:"type"`        //required
	Side        string `json:"side"`
	Quantity    string `json:"quantity"` //required
	TimeInForce string `json:"time_in_force"`
	Price       string `json:"price"`
	//Leverage       string `json:"leverage, omitempty"`
	//ExpireTime     int64  `json:"expire_time, omitempty"`
	//SubmissionTime int64  `json:"submission_time, omitempty"`
	Destination string `json:"destination"` //required
	//Source         string `json:"source"`
	Currency string `json:"currency"`
	//Text           string `json:"text"`
}

type OrderStatus string
type OrderSide string
type OrderTimeInForce string

func (t OrderStatus) s() string {
	s := t
	return string(s)
}
func (t OrderSide) s() string {
	s := t
	return string(s)
}
func (t OrderTimeInForce) s() string {
	s := t
	return string(s)
}
