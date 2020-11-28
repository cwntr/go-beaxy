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
			fmt.Printf("BTC available: %+v", a.AvailableForTrading)
		}
	}
}

func TestClient_GetOrderHistory(t *testing.T) {
	c := NewClient(TestAPIKey, getTestKeyContent())
	if c == nil {
		t.Fail()
		return
	}

	c.EnableDebugMode()
	orders, _, err := c.GetOrderHistory(10, time.Now())
	if err != nil {
		return
	}

	oo := *orders
	fmt.Printf("GetOrderHistory: %+v", oo)
	for _, o := range oo {
		_ = o
		fmt.Printf("GetOrderHistory detais: %+v", o)
	}
}

func TestClient_GetOrder(t *testing.T) {
	testOrderID := strings.ToUpper("7D7B8F89-2DBE-4C7D-AC43-476BC3C47B2B")
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
