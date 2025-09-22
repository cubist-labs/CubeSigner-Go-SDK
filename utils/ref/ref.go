// Package ref provides utility for creating a reference to absolute value.
package ref

func Of[T any](v T) *T {
	return &v
}
