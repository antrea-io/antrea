package connection

// L7ProtocolFields holds layer 7 protocols supported
type L7ProtocolFields struct {
	Http map[int32]*Http
}

// Http holds the L7 HTTP flow JSON values.
type Http struct {
	Hostname      string `json:"hostname"`
	URL           string `json:"url"`
	UserAgent     string `json:"http_user_agent"`
	ContentType   string `json:"http_content_type"`
	Method        string `json:"http_method"`
	Protocol      string `json:"protocol"`
	Status        int32  `json:"status"`
	ContentLength int32  `json:"length"`
}
