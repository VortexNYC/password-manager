package fill

func allowConfirm(h *Host) *Host {
	h.Confirm = func(string) error { return nil }
	return h
}
