# go-beaxy
Go client for Beaxy exchange Trading API.

Beaxy Trading API docs can be found here: [https://beaxyapiv2trading.docs.apiary.io/](https://beaxyapiv2trading.docs.apiary.io/)

Beaxy Exchange: [https://beaxy.com/](https://beaxy.com/)

## Get credentials
You need to register and verify an account on [beaxy.com](https://beaxy.com/). Once verified, go to your account API management and generate a new key which will generate you a unique `api-key` and `private key content` which are mandatory to connect to the Beaxy Trading API.


## REST client usage

### Initialize authorized client
    // init client which will create a session used for calculating request signature for every single request.
	c := NewClient("api-key", "private-key-content")
	if c == nil {
		fmt.Println("unable to initalize client")
	}

### Post order
	order := PostOrder {
		SecurityID: "XSNBTC",
		Type: "limit",
		Price: "0.00000720",
		Side: "sell",
		Quantity: "20",
		Destination: "MAXI",
		TimeInForce: "gtc",
		Currency: "XSN",
	}
	o, sc, err := c.PlaceOrder(order)
	if sc != 200 {
		fmt.Printf("err creating order: %+v \n", err)
	} else {
		fmt.Printf("success creating order: %+v \n", o)
	}

### Retrieve order

	singleOrder, sc, err := c.GetOrder(o.ID)
	if sc != 200 {
		fmt.Printf("err fetching order: %+v \n", err)
	} else {
		fmt.Printf("success fetching order: %+v \n", singleOrder)
	}

### Delete order	
	for _, o := range orders {
		err := c.DeleteOrder(o.ID)
		if err != nil {
			fmt.Printf("err deleting order: %+v \n", err)
		}
	}

### Fetch accounts (balances)

	accounts, _, err := c.GetAccounts()
	if err != nil {
		return
	}
	for _, a := range *accounts {
		if a.CurrencyID == "BTC" {
			fmt.Printf("BTC available: %+v", a.AvailableForTrading)
		}
	}
	

## Enable debug mode
	// will set log level to debug and print all details about request and response
	c.EnableDebugMode()
	
