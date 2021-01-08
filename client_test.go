package go_beaxy

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	TestAPIKey = "<api-key-here>"
)

func getTestKeyContent() string {
	return `<private-key-content-here>
`
}




func TestClient_OrderFlow(t *testing.T) {
	c := NewClient(TestAPIKey, getTestKeyContent())
	if c == nil {
		t.Fail()
		return
	}

	c.EnableDebugMode()

	order := PostOrder{
		SecurityID:  SymbolXSNBTC,
		Type:        "limit",
		Price:       "0.00000500",
		Side:        Buy.S(),
		Quantity:    "21",
		Destination: "MAXI",
		TimeInForce: "gtc",
		Currency:    "XSN",
	}
	o, sc, err := c.PlaceOrder(order)
	if sc != 200 {
		fmt.Printf("err creating order: %+v \n", err)
	} else {
		fmt.Printf("success creating order: %+v \n", o)
	}

	time.Sleep(time.Second * 1)

	singleOrder, sc, err := c.GetOrder(o.ID)
	if sc != 200 {
		fmt.Printf("err fetching order: %+v \n", err)
	} else {
		fmt.Printf("success fetching order: %+v \n", singleOrder)
	}

	time.Sleep(time.Second * 1)
	for _, o := range *singleOrder {
		err := c.DeleteOrder(o.ID)
		if err != nil {
			fmt.Printf("err deleting order: %+v \n", err)
		}
	}
}

func TestClient_Accounts(t *testing.T) {
	c := NewClient(TestAPIKey, getTestKeyContent())
	if c == nil {
		t.Fail()
		return
	}

	c.EnableDebugMode()

	accounts, _, err := c.GetAccounts()
	if err != nil {
		return
	}
	for _, a := range *accounts {
		if a.CurrencyID == "BTC" {
			fmt.Printf("BTC available: %+v", a)
		}
	}
}

func TestClient_GetOrderHistory(t *testing.T) {
	c := NewClient(TestAPIKey, getTestKeyContent())
	if c == nil {
		t.Fail()
		return
	}

	//c.EnableDebugMode()
	now := time.Now()
	before := now.Add(time.Duration(-20) * time.Minute)
	//get first 10 orders from last week
	orders, sc, err := c.GetOrderHistory(150000000, before)
	if err != nil {
		fmt.Printf("err: (sc: %d) %+v\n", sc, err)
		return
	}

	fmt.Printf("rsp: (sc: %d)\n ", sc)
	oo := *orders
	fmt.Printf("GetOrderHistory:%d\n", len(oo))
	for _, o := range oo {
		_ = o
		if o.ID == strings.ToUpper("7844db4a-be43-4163-a05a-8f97de55fe90") {
			fmt.Printf("GetOrderHistory detais: %+v", o)
		}
	}
}

func TestClient_GetOrder(t *testing.T) {
	testOrderID := strings.ToUpper("A32B8F89-2DB3-4C1D-AC43-476BDCC47B3B")
	c := NewClient(TestAPIKey, getTestKeyContent())
	if c == nil {
		t.Fail()
		return
	}

	c.EnableDebugMode()
	orders, _, err := c.GetOrder(testOrderID)
	if err != nil {
		return
	}

	oo := *orders
	fmt.Printf("orders: %+v", oo)
	for _, o := range oo {
		_ = o
		fmt.Printf("order detais: %+v", o)
	}
}

func TestClient_GetRecentOrderHistory(t *testing.T) {
	c := NewClient(TestAPIKey, getTestKeyContent())
	if c == nil {
		t.Fail()
		return
	}

	c.EnableDebugMode()
	now := time.Now()
	before := now.Add(time.Duration(-24) * time.Hour)
	orders, sc, err := c.GetOrderHistory(2000, before)
	if err != nil || sc > 200 {
		t.Fail()
	}

	oo := *orders
	fmt.Printf("orders: %+v", oo)
	for _, o := range oo {
		_ = o
		fmt.Printf("order detais: %+v", o)
	}
}

func TestClient_Orderbook(t *testing.T) {
	c := NewClient(TestAPIKey, getTestKeyContent())
	orderbook, err := c.GetOrderbook("XSNBTC", 5)
	fmt.Printf("orderbook: %v\n", orderbook)
	fmt.Printf("err: %v\n", err)

	for _, o := range orderbook.Entries{
		fmt.Printf("side: %s price: %.8f \n", o.Side, o.Price)
	}
}