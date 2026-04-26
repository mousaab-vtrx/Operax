package pagination

// PageInfo describes pagination parameters.
type PageInfo struct {
	Offset int
	Limit  int
}

// Result wraps paginated results with metadata.
type Result[T any] struct {
	Items      []T
	Total      int
	Offset     int
	Limit      int
	HasNext    bool
	HasPrev    bool
	NextOffset int
	PrevOffset int
}

// NewPageInfo creates pagination parameters with validation.
// If limit is 0 or negative, defaults to 50.
// If offset is negative, defaults to 0.
func NewPageInfo(offset, limit int) PageInfo {
	if limit <= 0 {
		limit = 50
	}
	if limit > 10000 {
		limit = 10000 // Cap at 10000 to prevent memory exhaustion
	}
	if offset < 0 {
		offset = 0
	}
	return PageInfo{Offset: offset, Limit: limit}
}

// NewResult creates a paginated result set.
func NewResult[T any](items []T, total, offset, limit int) Result[T] {
	hasNext := offset+limit < total
	hasPrev := offset > 0
	nextOffset := offset + limit
	if !hasNext {
		nextOffset = offset
	}
	prevOffset := offset - limit
	if prevOffset < 0 {
		prevOffset = 0
	}

	return Result[T]{
		Items:      items,
		Total:      total,
		Offset:     offset,
		Limit:      limit,
		HasNext:    hasNext,
		HasPrev:    hasPrev,
		NextOffset: nextOffset,
		PrevOffset: prevOffset,
	}
}
