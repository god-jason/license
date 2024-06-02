package license

import "github.com/super-l/machine-code/machine"

func MachineID() (string, error) {
	return machine.GetCpuSerialNumber()
}
