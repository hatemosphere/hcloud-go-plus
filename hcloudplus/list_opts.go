package hcloudplus

import (
	"net/url"
	"strconv"
)

// ListOpts is the common page/per_page pagination input used by most list
// endpoints on the private API.
type ListOpts struct {
	Page    int // 1-indexed; 0 means server default.
	PerPage int // 0 means server default.
}

func (o ListOpts) values() url.Values {
	v := url.Values{}
	if o.Page > 0 {
		v.Set("page", strconv.Itoa(o.Page))
	}
	if o.PerPage > 0 {
		v.Set("per_page", strconv.Itoa(o.PerPage))
	}
	return v
}

// Meta is the pagination envelope common to every list endpoint.
type Meta struct {
	Pagination Pagination `json:"pagination"`
}

// Pagination carries page-based pagination fields. Cursor-based endpoints
// (e.g. /_activities) populate Cursor + PerPage only.
type Pagination struct {
	Page         int    `json:"page,omitempty"`
	PerPage      int    `json:"per_page"`
	PreviousPage int    `json:"previous_page,omitempty"`
	NextPage     int    `json:"next_page,omitempty"`
	LastPage     int    `json:"last_page,omitempty"`
	TotalEntries int    `json:"total_entries,omitempty"`
	Cursor       string `json:"cursor,omitempty"`
}
