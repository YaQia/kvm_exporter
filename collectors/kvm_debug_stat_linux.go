package collectors

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/Faione/easyxporter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

const (
	KVM_DEBUG_DIR  = "/sys/kernel/debug/kvm"
	KVM_DEBUG_STAT = "kvm_stat"
	MAX_DEPTH      = 2
)

var (
	depth       = easyxporter.Flags().Int("collector.dir.depth", 2, "KVM Debug Stat Depth")
	vmMapPath   = easyxporter.Flags().String("collector.vmmap.path", "vm_map.yaml", "VmMap yaml path")
	kvmDebugDir = easyxporter.Flags().String("collector.kvmdebug.dir", KVM_DEBUG_DIR, "KVM debug stat dir")
)

type kvmDebugStatCollector struct {
	logger    *logrus.Logger
	dynLabels []string
	vmMap     atomic.Value
}

func NewKvmDebugStatCollector(logger *logrus.Logger) (easyxporter.Collector, error) {
	var atomicVmMap atomic.Value

	if err := checkKVMDebugDir(); err != nil {
		return nil, err
	}

	if vmMap, err := ReadVmMapFromFile(*vmMapPath); err != nil {
		return nil, err
	} else {

		mp := make(DirMap)
		for k, v := range vmMap.VmInfos {
			mp[v.KvmDebugDir] = k
		}

		atomicVmMap.Store(mp)
	}

	logger.Debugf("watching kvm debug path: %s", *kvmDebugDir)
	return &kvmDebugStatCollector{logger: logger, dynLabels: []string{"domain"}, vmMap: atomicVmMap}, nil
}

func (c *kvmDebugStatCollector) Update(ch chan<- prometheus.Metric) error {
	dirMap := c.vmMap.Load().(DirMap)

	kvmDirWalkF := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			rd := strings.Count(*kvmDebugDir, string(filepath.Separator))
			d := strings.Count(path, string(filepath.Separator))

			if d-rd > *depth {
				c.logger.Debugf("skip dir: %s", path)
				return filepath.SkipDir
			}

			return nil
		}

		bt, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		labelDomain, err := dirMap.dirPathToLabel(filepath.Dir(path))
		if err != nil {
			return err
		}

		vstr := strings.TrimRight(string(bt), "\n")
		v, err := strconv.Atoi(vstr)
		if err != nil {
			return err
		}

		metric := filepath.Base(path)

		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc(
			prometheus.BuildFQName(KVM_DEBUG_STAT, metric, "count"),
			fmt.Sprintf("%s count from %s", metric, *kvmDebugDir),
			c.dynLabels, nil,
		),
			prometheus.GaugeValue,
			float64(v),
			labelDomain,
		)

		return nil
	}

	return filepath.Walk(*kvmDebugDir, kvmDirWalkF)
}

func init() {
	easyxporter.RegisterCollector(KVM_DEBUG_STAT, true, NewKvmDebugStatCollector)
}
