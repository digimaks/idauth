//nolint:tagliatelle
package smartid

type PostSmartIDResponse struct {
	Status      int    `json:"status,omitempty"`
	Code        string `json:"code,omitempty"`
	Nonce       string `json:"nonce,omitempty"`
	Challenge   string `json:"challenge,omitempty"`
	SecondsLeft int    `json:"seconds_left,omitempty"`
}
