package thumb

import "syscall"

// syscallNRaw calls a COM vtable function pointer.
func syscallNRaw(fn uintptr, args ...uintptr) (uintptr, uintptr, error) {
	r1, r2, err := syscall.SyscallN(fn, args...)
	return r1, r2, err
}
