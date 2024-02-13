package collectors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/Faione/easyxporter"
	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

const (
	KVM_DEBUG_DIR  = "/sys/kernel/debug/kvm"
	KVM_DEBUG_STAT = "kvm_stat"
	MAX_DEPTH      = 2
)

var (
	depth       = easyxporter.Flags().Int("collector.dir.depth", MAX_DEPTH, "KVM Debug Stat Depth")
	vmMapPath   = easyxporter.Flags().String("collector.vmmap.path", "/etc/vm.yaml", "VmMap yaml path")
	kvmDebugDir = easyxporter.Flags().String("collector.kvmdebug.dir", KVM_DEBUG_DIR, "KVM debug stat dir")
)

type kvmDebugStatCollector struct {
	logger *logrus.Logger
	vmMap  atomic.Value
}

func NewKvmDebugStatCollector(logger *logrus.Logger) (easyxporter.AsyncCollector, error) {
	var atomicVmMap atomic.Value

	if err := checkKVMDebugDir(); err != nil {
		return nil, err
	}

	if _, err := os.Stat(*vmMapPath); err != nil {
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

	return &kvmDebugStatCollector{logger: logger, vmMap: atomicVmMap}, nil
}

func (c *kvmDebugStatCollector) Update(ch chan<- prometheus.Metric) error {
	dirMap := c.vmMap.Load().(DirMap)

	kvmDirWalkF := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		c.logger.Debugf("parsing dir: %s", path)
		if info.IsDir() {
			rd := strings.Count(*kvmDebugDir, string(filepath.Separator))
			d := strings.Count(path, string(filepath.Separator))

			if d-rd > *depth {
				return filepath.SkipDir
			}

			return nil
		}

		bt, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read file %s failed: %s", path, err)
		}

		labels, err := dirMap.dirPathToLabel(filepath.Dir(path))
		if err != nil {
			return fmt.Errorf("read label from %s failed: %s", filepath.Dir(path), err)
		}

		content := string(bt)
		if content == "" {
			return nil
		}

		vstr := strings.TrimRight(content, "\n")
		v, err := strconv.Atoi(vstr)
		if err != nil {
			return fmt.Errorf("parse value from %s failed: %s", path, err)
		}

		metric := filepath.Base(path)
		dynLabels := []string{"domain"}

		// in vcpu dir, some filename can not set to metric name
		if len(labels) == 2 {
			metric = fmt.Sprintf("vcpu_%s", strings.ReplaceAll(metric, "-", "_"))
			dynLabels = []string{"domain", "vcpu"}
		}

		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(KVM_DEBUG_STAT, metric, "count"),
				fmt.Sprintf("%s count from %s", metric, *kvmDebugDir),
				dynLabels, nil,
			),
			prometheus.GaugeValue,
			float64(v),
			labels...,
		)

		return nil
	}

	return filepath.Walk(*kvmDebugDir, kvmDirWalkF)
}

func (c *kvmDebugStatCollector) AsyncCollect(ctx context.Context) error {

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

WATCHER_LOOP:
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return fmt.Errorf("unable to watch %s", *vmMapPath)
			}

			// write event
			if event.Op&fsnotify.Write == fsnotify.Write {
				c.logger.Info("config modified")

				vmMap, err := ReadVmMapFromFile(*vmMapPath)
				if err != nil {
					c.logger.Errorf("unable to parse config: %s", err)
					continue
				}

				c.vmMap.Store(vmMap)
			}

		case <-ctx.Done():
			break WATCHER_LOOP

		}

	}

	return nil
}

func init() {
	easyxporter.RegisterAsyncCollector(KVM_DEBUG_STAT, true, NewKvmDebugStatCollector)
}
