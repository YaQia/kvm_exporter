package collectors

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type DirMap map[string]string

func (dirMap DirMap) dirPathToLabel(dirPath string) (string, error) {
	if len(dirPath) < len(*kvmDebugDir) {
		return "", errors.New("invalid dir path")
	}

	if dirPath == *kvmDebugDir {
		return "global", nil
	}

	var paths []string
	for dirPath != *kvmDebugDir {
		paths = append(paths, filepath.Base(dirPath))
		dirPath = filepath.Dir(dirPath)
	}

	var (
		spid string
		vcpu string
	)

	switch len(paths) {
	case 1:
		spid = paths[0]
	case 2:
		spid = paths[1]
		vcpu = paths[0]
	default:
		return "", errors.New("out of max depth")
	}

	vm, ok := dirMap[spid]
	if !ok {
		return "", fmt.Errorf("pid %s to vm failed", spid)
	}

	if vcpu != "" {
		return vm + "_" + vcpu, nil
	}

	return vm, nil
}

type VmInfo struct {
	Pid         string `yaml:"pid"`
	KvmDebugDir string `yaml:"kvm_debug_dir"`
}

type VmMap struct {
	VmInfos map[string]VmInfo `yaml:"vm_infos"`
}

func ReadVmMapFromFile(path string) (*VmMap, error) {
	bt, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	vmMap := &VmMap{}
	if err := yaml.Unmarshal(bt, vmMap); err != nil {
		return nil, err
	}
	return vmMap, nil
}

func checkKVMDebugDir() error {
	if os.Getegid() != 0 {
		return errors.New("non-root user can't access kvm debug dir")
	}

	if _, err := os.Stat(*kvmDebugDir); err != nil {
		return fmt.Errorf("kvm debug not mount: %s", err)
	}

	return nil
}
