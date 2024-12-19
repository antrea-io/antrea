package fqdncache

import (
	"encoding/json"
	"io"

	"antrea.io/antrea/pkg/agent/types"
)

type Response struct {
	*types.DnsCacheEntry
}

func objTransform(o interface{}, _ map[string]string) (interface{}, error) {
	return Response{o.(*types.DnsCacheEntry)}, nil
}

func listTransform(l interface{}, _ map[string]string) (interface{}, error) {
	result := l.([]Response)
	return result, nil
}

func Transform(reader io.Reader, single bool, opts map[string]string) (interface{}, error) {
	b, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	var resp []Response
	err = json.Unmarshal(b, &resp)
	if err != nil {
		return nil, err
	}
	domain, exists := opts["domain"]
	if exists {
		var filteredResp []Response
		for _, r := range resp {
			if r.FqdnName == domain {
				filteredResp = append(filteredResp, r)
			}
		}
		resp = filteredResp
	}
	if len(resp) == 0 {
		return "", nil
	}
	return resp, nil
}

func (r Response) GetTableHeader() []string {
	return []string{"FQDN", "ADDRESS", "EXPIRATION TIME"}
}

func (r Response) GetTableRow(maxColumnLength int) []string {
	return []string{
		r.FqdnName,
		r.IpAddress.String(),
		r.ExpirationTime.String(),
	}
}

func (r Response) SortRows() bool {
	return false
}
