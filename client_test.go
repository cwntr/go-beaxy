package go_beaxy

import (
	"fmt"
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
		Price:       "0.00000720",
		Side:        Sell.s(),
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
