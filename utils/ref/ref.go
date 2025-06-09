package ref

func Of[T any](v T) *T {
	return &v
}
