//go:build !unix

package main

func maybeReexecDemoAsUnprivileged(args []string) (bool, int, error) { return false, 0, nil }
