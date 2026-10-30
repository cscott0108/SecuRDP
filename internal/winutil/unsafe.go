package winutil

import "unsafe"

func unsafePtr[T any](p *T) unsafe.Pointer { return unsafe.Pointer(p) }
