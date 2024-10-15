package rest

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

const UPGRADESERVER_URI = "127.0.0.1:8081"

func (c *Context) upgrade(w http.ResponseWriter, r *http.Request) {
	client := http.Client{
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequest(r.Method, "http://"+UPGRADESERVER_URI+"/upgrade", nil)
	if err != nil {
		c.returnError(w, fmt.Errorf("upgrade request error: %s", err), http.StatusBadRequest)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		c.returnError(w, fmt.Errorf("upgrade error: %s", err), http.StatusBadRequest)
		return
	}
	if resp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			c.returnError(w, fmt.Errorf("upgrade error: got status code: %d. Respons: %s", resp.StatusCode, bodyBytes), http.StatusBadRequest)
			return
		}
		c.returnError(w, fmt.Errorf("upgrade error: got status code: %d. Couldn't get response", resp.StatusCode), http.StatusBadRequest)
		return
	}

	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		c.returnError(w, fmt.Errorf("body read error: %s", err), http.StatusBadRequest)
		return
	}

	c.write(w, bodyBytes)

}
