package model

// KDFParams contains parameters for password-based key derivation.
type KDFParams struct {
	Time   uint32 `json:"time"`
	MemKiB uint32 `json:"mem_kib"`
	Par    uint8  `json:"par"`
}

// NewKDFParams creates KDFParams with given time, memory and parallelism.
func NewKDFParams(time uint32, memKiB uint32, par uint8) KDFParams {
	return KDFParams{
		Time:   time,
		MemKiB: memKiB,
		Par:    par,
	}
}
