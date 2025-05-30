package disk

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/common/psutil"
	"github.com/influxdata/telegraf/testutil"
)

func TestDiskUsage(t *testing.T) {
	mck := &mock.Mock{}
	mps := psutil.MockPSDisk{SystemPS: &psutil.SystemPS{PSDiskDeps: &psutil.MockDiskUsage{Mock: mck}}, Mock: mck}
	defer mps.AssertExpectations(t)

	var acc testutil.Accumulator
	var err error

	psAll := []disk.PartitionStat{
		{
			Device:     "/dev/sda",
			Mountpoint: "/",
			Fstype:     "ext4",
			Opts:       []string{"ro", "noatime", "nodiratime"},
		},
		{
			Device:     "/dev/sdb",
			Mountpoint: "/home",
			Fstype:     "ext4",
			Opts:       []string{"rw", "noatime", "nodiratime", "errors=remount-ro"},
		},
		{
			Device:     "/dev/sda",
			Mountpoint: "/var/rootbind",
			Fstype:     "ext4",
			Opts:       []string{"ro", "noatime", "nodiratime", "bind"},
		},
	}
	duAll := []disk.UsageStat{
		{
			Path:        "/",
			Fstype:      "ext4",
			Total:       128,
			Free:        23,
			Used:        100,
			InodesTotal: 1234,
			InodesFree:  234,
			InodesUsed:  1000,
		},
		{
			Path:        "/home",
			Fstype:      "ext4",
			Total:       256,
			Free:        46,
			Used:        200,
			InodesTotal: 2468,
			InodesFree:  468,
			InodesUsed:  2000,
		},
		{
			Path:        "/var/rootbind",
			Fstype:      "ext4",
			Total:       128,
			Free:        23,
			Used:        100,
			InodesTotal: 1234,
			InodesFree:  234,
			InodesUsed:  1000,
		},
	}

	mps.On("Partitions", true).Return(psAll, nil)
	mps.On("OSGetenv", "HOST_MOUNT_PREFIX").Return("")
	mps.On("PSDiskUsage", "/").Return(&duAll[0], nil)
	mps.On("PSDiskUsage", "/home").Return(&duAll[1], nil)
	mps.On("PSDiskUsage", "/var/rootbind").Return(&duAll[2], nil)

	err = (&Disk{ps: mps}).Gather(&acc)
	require.NoError(t, err)

	numDiskMetrics := acc.NFields()
	expectedAllDiskMetrics := 24
	require.Equal(t, expectedAllDiskMetrics, numDiskMetrics)

	tags1 := map[string]string{
		"path":   string(os.PathSeparator),
		"fstype": "ext4",
		"device": "sda",
		"mode":   "ro",
	}
	tags2 := map[string]string{
		"path":   fmt.Sprintf("%chome", os.PathSeparator),
		"fstype": "ext4",
		"device": "sdb",
		"mode":   "rw",
	}
	tags3 := map[string]string{
		"path":   fmt.Sprintf("%cvar%crootbind", os.PathSeparator, os.PathSeparator),
		"fstype": "ext4",
		"device": "sda",
		"mode":   "ro",
	}

	fields1 := map[string]interface{}{
		"total":               uint64(128),
		"used":                uint64(100),
		"free":                uint64(23),
		"inodes_total":        uint64(1234),
		"inodes_free":         uint64(234),
		"inodes_used":         uint64(1000),
		"used_percent":        float64(81.30081300813008),
		"inodes_used_percent": float64(81.03727714748784),
	}
	fields2 := map[string]interface{}{
		"total":               uint64(256),
		"used":                uint64(200),
		"free":                uint64(46),
		"inodes_total":        uint64(2468),
		"inodes_free":         uint64(468),
		"inodes_used":         uint64(2000),
		"used_percent":        float64(81.30081300813008),
		"inodes_used_percent": float64(81.03727714748784),
	}
	fields3 := map[string]interface{}{
		"total":               uint64(128),
		"used":                uint64(100),
		"free":                uint64(23),
		"inodes_total":        uint64(1234),
		"inodes_free":         uint64(234),
		"inodes_used":         uint64(1000),
		"used_percent":        float64(81.30081300813008),
		"inodes_used_percent": float64(81.03727714748784),
	}
	acc.AssertContainsTaggedFields(t, "disk", fields1, tags1)
	acc.AssertContainsTaggedFields(t, "disk", fields2, tags2)
	acc.AssertContainsTaggedFields(t, "disk", fields3, tags3)

	// We expect 7 more DiskMetrics to show up with an explicit match on "/"
	// and /home not matching the /dev in MountPoints
	err = (&Disk{ps: &mps, MountPoints: []string{"/", "/dev"}}).Gather(&acc)
	require.NoError(t, err)
	require.Equal(t, expectedAllDiskMetrics+8, acc.NFields())

	// We should see all the diskpoints as MountPoints includes both
	// /, /home, and /var/rootbind
	err = (&Disk{ps: &mps, MountPoints: []string{"/", "/home", "/var/rootbind"}}).Gather(&acc)
	require.NoError(t, err)
	require.Equal(t, expectedAllDiskMetrics+8*4, acc.NFields())

	// We should see all the mounts as MountPoints except the bind mound
	err = (&Disk{ps: &mps, IgnoreMountOpts: []string{"bind"}}).Gather(&acc)
	require.NoError(t, err)
	require.Equal(t, expectedAllDiskMetrics+8*6, acc.NFields())
}

func TestDiskUsageHostMountPrefix(t *testing.T) {
	tests := []struct {
		name            string
		partitionStats  []disk.PartitionStat
		usageStats      []*disk.UsageStat
		hostMountPrefix string
		expectedTags    map[string]string
		expectedFields  map[string]interface{}
	}{
		{
			name: "no host mount prefix",
			partitionStats: []disk.PartitionStat{
				{
					Device:     "/dev/sda",
					Mountpoint: "/",
					Fstype:     "ext4",
					Opts:       []string{"ro"},
				},
			},
			usageStats: []*disk.UsageStat{
				{
					Path:  "/",
					Total: 42,
				},
			},
			expectedTags: map[string]string{
				"path":   string(os.PathSeparator),
				"device": "sda",
				"fstype": "ext4",
				"mode":   "ro",
			},
			expectedFields: map[string]interface{}{
				"total":               uint64(42),
				"used":                uint64(0),
				"free":                uint64(0),
				"inodes_total":        uint64(0),
				"inodes_free":         uint64(0),
				"inodes_used":         uint64(0),
				"used_percent":        float64(0),
				"inodes_used_percent": float64(0),
			},
		},
		{
			name: "host mount prefix",
			partitionStats: []disk.PartitionStat{
				{
					Device:     "/dev/sda",
					Mountpoint: "/hostfs/var",
					Fstype:     "ext4",
					Opts:       []string{"ro"},
				},
			},
			usageStats: []*disk.UsageStat{
				{
					Path:  "/hostfs/var",
					Total: 42,
				},
			},
			hostMountPrefix: "/hostfs",
			expectedTags: map[string]string{
				"path":   fmt.Sprintf("%cvar", os.PathSeparator),
				"device": "sda",
				"fstype": "ext4",
				"mode":   "ro",
			},
			expectedFields: map[string]interface{}{
				"total":               uint64(42),
				"used":                uint64(0),
				"free":                uint64(0),
				"inodes_total":        uint64(0),
				"inodes_free":         uint64(0),
				"inodes_used":         uint64(0),
				"used_percent":        float64(0),
				"inodes_used_percent": float64(0),
			},
		},
		{
			name: "host mount prefix exact match",
			partitionStats: []disk.PartitionStat{
				{
					Device:     "/dev/sda",
					Mountpoint: "/hostfs",
					Fstype:     "ext4",
					Opts:       []string{"ro"},
				},
			},
			usageStats: []*disk.UsageStat{
				{
					Path:  "/hostfs",
					Total: 42,
				},
			},
			hostMountPrefix: "/hostfs",
			expectedTags: map[string]string{
				"path":   string(os.PathSeparator),
				"device": "sda",
				"fstype": "ext4",
				"mode":   "ro",
			},
			expectedFields: map[string]interface{}{
				"total":               uint64(42),
				"used":                uint64(0),
				"free":                uint64(0),
				"inodes_total":        uint64(0),
				"inodes_free":         uint64(0),
				"inodes_used":         uint64(0),
				"used_percent":        float64(0),
				"inodes_used_percent": float64(0),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mck := &mock.Mock{}
			mps := psutil.MockPSDisk{SystemPS: &psutil.SystemPS{PSDiskDeps: &psutil.MockDiskUsage{Mock: mck}}, Mock: mck}
			defer mps.AssertExpectations(t)

			var acc testutil.Accumulator
			var err error

			mps.On("Partitions", true).Return(tt.partitionStats, nil)

			for _, v := range tt.usageStats {
				mps.On("PSDiskUsage", v.Path).Return(v, nil)
			}

			mps.On("OSGetenv", "HOST_MOUNT_PREFIX").Return(tt.hostMountPrefix)

			err = (&Disk{ps: mps}).Gather(&acc)
			require.NoError(t, err)

			acc.AssertContainsTaggedFields(t, "disk", tt.expectedFields, tt.expectedTags)
		})
	}
}

func TestDiskStats(t *testing.T) {
	var mps psutil.MockPS
	defer mps.AssertExpectations(t)
	var acc testutil.Accumulator
	var err error

	duAll := []*disk.UsageStat{
		{
			Path:        "/",
			Fstype:      "ext4",
			Total:       128,
			Free:        23,
			Used:        100,
			InodesTotal: 1234,
			InodesFree:  234,
			InodesUsed:  1000,
		},
		{
			Path:        "/home",
			Fstype:      "ext4",
			Total:       256,
			Free:        46,
			Used:        200,
			InodesTotal: 2468,
			InodesFree:  468,
			InodesUsed:  2000,
		},
		{
			Path:        "/var/rootbind",
			Fstype:      "ext4",
			Total:       128,
			Free:        23,
			Used:        100,
			InodesTotal: 1234,
			InodesFree:  234,
			InodesUsed:  1000,
		},
	}
	duMountFiltered := []*disk.UsageStat{
		{
			Path:        "/",
			Fstype:      "ext4",
			Total:       128,
			Free:        23,
			Used:        100,
			InodesTotal: 1234,
			InodesFree:  234,
			InodesUsed:  1000,
		},
	}
	duOptFiltered := []*disk.UsageStat{
		{
			Path:        "/",
			Fstype:      "ext4",
			Total:       128,
			Free:        23,
			Used:        100,
			InodesTotal: 1234,
			InodesFree:  234,
			InodesUsed:  1000,
		},
		{
			Path:        "/home",
			Fstype:      "ext4",
			Total:       256,
			Free:        46,
			Used:        200,
			InodesTotal: 2468,
			InodesFree:  468,
			InodesUsed:  2000,
		},
	}

	psAll := []*disk.PartitionStat{
		{
			Device:     "/dev/sda",
			Mountpoint: "/",
			Fstype:     "ext4",
			Opts:       []string{"ro", "noatime", "nodiratime"},
		},
		{
			Device:     "/dev/sdb",
			Mountpoint: "/home",
			Fstype:     "ext4",
			Opts:       []string{"rw", "noatime", "nodiratime", "errors=remount-ro"},
		},
		{
			Device:     "/dev/sda",
			Mountpoint: "/var/rootbind",
			Fstype:     "ext4",
			Opts:       []string{"ro", "noatime", "nodiratime", "bind"},
		},
	}

	psMountFiltered := []*disk.PartitionStat{
		{
			Device:     "/dev/sda",
			Mountpoint: "/",
			Fstype:     "ext4",
			Opts:       []string{"ro", "noatime", "nodiratime"},
		},
	}
	psOptFiltered := []*disk.PartitionStat{
		{
			Device:     "/dev/sda",
			Mountpoint: "/",
			Fstype:     "ext4",
			Opts:       []string{"ro", "noatime", "nodiratime"},
		},
		{
			Device:     "/dev/sdb",
			Mountpoint: "/home",
			Fstype:     "ext4",
			Opts:       []string{"rw", "noatime", "nodiratime", "errors=remount-ro"},
		},
	}

	mps.On("DiskUsage", []string(nil), []string(nil), []string(nil)).Return(duAll, psAll, nil)
	mps.On("DiskUsage", []string{"/", "/dev"}, []string(nil), []string(nil)).Return(duMountFiltered, psMountFiltered, nil)
	mps.On("DiskUsage", []string{"/", "/home", "/var/rootbind"}, []string(nil), []string(nil)).Return(duAll, psAll, nil)
	mps.On("DiskUsage", []string(nil), []string{"bind"}, []string(nil)).Return(duOptFiltered, psOptFiltered, nil)

	err = (&Disk{ps: &mps}).Gather(&acc)
	require.NoError(t, err)

	numDiskMetrics := acc.NFields()
	expectedAllDiskMetrics := 24
	require.Equal(t, expectedAllDiskMetrics, numDiskMetrics)

	tags1 := map[string]string{
		"path":   "/",
		"fstype": "ext4",
		"device": "sda",
		"mode":   "ro",
	}
	tags2 := map[string]string{
		"path":   "/home",
		"fstype": "ext4",
		"device": "sdb",
		"mode":   "rw",
	}

	fields1 := map[string]interface{}{
		"total":               uint64(128),
		"used":                uint64(100),
		"free":                uint64(23),
		"inodes_total":        uint64(1234),
		"inodes_free":         uint64(234),
		"inodes_used":         uint64(1000),
		"used_percent":        float64(81.30081300813008),
		"inodes_used_percent": float64(81.03727714748784),
	}
	fields2 := map[string]interface{}{
		"total":               uint64(256),
		"used":                uint64(200),
		"free":                uint64(46),
		"inodes_total":        uint64(2468),
		"inodes_free":         uint64(468),
		"inodes_used":         uint64(2000),
		"used_percent":        float64(81.30081300813008),
		"inodes_used_percent": float64(81.03727714748784),
	}
	acc.AssertContainsTaggedFields(t, "disk", fields1, tags1)
	acc.AssertContainsTaggedFields(t, "disk", fields2, tags2)

	// We expect 7 more DiskMetrics to show up with an explicit match on "/"
	// and /home and /var/rootbind not matching the /dev in MountPoints
	err = (&Disk{ps: &mps, MountPoints: []string{"/", "/dev"}}).Gather(&acc)
	require.NoError(t, err)
	require.Equal(t, expectedAllDiskMetrics+8, acc.NFields())

	// We should see all the diskpoints as MountPoints includes both
	// /, /home, and /var/rootbind
	err = (&Disk{ps: &mps, MountPoints: []string{"/", "/home", "/var/rootbind"}}).Gather(&acc)
	require.NoError(t, err)
	require.Equal(t, expectedAllDiskMetrics+8*4, acc.NFields())

	// We should see all the mounts as MountPoints except the bind mound
	err = (&Disk{ps: &mps, IgnoreMountOpts: []string{"bind"}}).Gather(&acc)
	require.NoError(t, err)
	require.Equal(t, expectedAllDiskMetrics+8*6, acc.NFields())
}

func TestDiskUsageIssues(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping due to Linux-only test-cases...")
	}

	tests := []struct {
		name     string
		prefix   string
		du       disk.UsageStat
		expected []telegraf.Metric
	}{
		{
			name:   "success",
			prefix: "",
			du: disk.UsageStat{
				Total:       256,
				Free:        46,
				Used:        200,
				InodesTotal: 2468,
				InodesFree:  468,
				InodesUsed:  2000,
			},
			expected: []telegraf.Metric{
				testutil.MustMetric(
					"disk",
					map[string]string{
						"device": "tmpfs",
						"fstype": "tmpfs",
						"mode":   "rw",
						"path":   "/tmp",
					},
					map[string]interface{}{
						"total":               uint64(256),
						"used":                uint64(200),
						"free":                uint64(46),
						"inodes_total":        uint64(2468),
						"inodes_free":         uint64(468),
						"inodes_used":         uint64(2000),
						"used_percent":        float64(81.30081300813008),
						"inodes_used_percent": float64(81.03727714748784),
					},
					time.Unix(0, 0),
					telegraf.Gauge,
				),
				testutil.MustMetric(
					"disk",
					map[string]string{
						"device": "nvme0n1p4",
						"fstype": "ext4",
						"mode":   "rw",
						"path":   "/",
					},
					map[string]interface{}{
						"total":               uint64(256),
						"used":                uint64(200),
						"free":                uint64(46),
						"inodes_total":        uint64(2468),
						"inodes_free":         uint64(468),
						"inodes_used":         uint64(2000),
						"used_percent":        float64(81.30081300813008),
						"inodes_used_percent": float64(81.03727714748784),
					},
					time.Unix(0, 0),
					telegraf.Gauge,
				),
			},
		},
		{
			name:   "issue 10297",
			prefix: "/host",
			du: disk.UsageStat{
				Total:       256,
				Free:        46,
				Used:        200,
				InodesTotal: 2468,
				InodesFree:  468,
				InodesUsed:  2000,
			},
			expected: []telegraf.Metric{
				testutil.MustMetric(
					"disk",
					map[string]string{
						"device": "sda1",
						"fstype": "ext4",
						"label":  "root",
						"mode":   "rw",
						"path":   "/",
					},
					map[string]interface{}{
						"total":               uint64(256),
						"used":                uint64(200),
						"free":                uint64(46),
						"inodes_total":        uint64(2468),
						"inodes_free":         uint64(468),
						"inodes_used":         uint64(2000),
						"used_percent":        float64(81.30081300813008),
						"inodes_used_percent": float64(81.03727714748784),
					},
					time.Unix(0, 0),
					telegraf.Gauge,
				),
				testutil.MustMetric(
					"disk",
					map[string]string{
						"device": "sdb",
						"fstype": "ext4",
						"label":  "storage",
						"mode":   "rw",
						"path":   "/mnt/storage",
					},
					map[string]interface{}{
						"total":               uint64(256),
						"used":                uint64(200),
						"free":                uint64(46),
						"inodes_total":        uint64(2468),
						"inodes_free":         uint64(468),
						"inodes_used":         uint64(2000),
						"used_percent":        float64(81.30081300813008),
						"inodes_used_percent": float64(81.03727714748784),
					},
					time.Unix(0, 0),
					telegraf.Gauge,
				),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup the environment
			hostMountPrefix := tt.prefix

			hostProcPrefix, err := filepath.Abs(filepath.Join("testdata", strings.ReplaceAll(tt.name, " ", "_"), "proc"))
			require.NoError(t, err)

			hostSysPrefix, err := filepath.Abs(filepath.Join("testdata", strings.ReplaceAll(tt.name, " ", "_"), "sys"))
			require.NoError(t, err)

			// Get the partitions in the test-case
			os.Clearenv()
			t.Setenv("HOST_PROC", hostProcPrefix)
			t.Setenv("HOST_SYS", hostSysPrefix)

			partitions, err := disk.Partitions(true)
			require.NoError(t, err)

			// Mock the disk usage
			mck := &mock.Mock{}
			mps := psutil.MockPSDisk{SystemPS: &psutil.SystemPS{PSDiskDeps: &psutil.MockDiskUsage{Mock: mck}}, Mock: mck}
			defer mps.AssertExpectations(t)

			mps.On("Partitions", true).Return(partitions, nil)

			for _, partition := range partitions {
				mountpoint := partition.Mountpoint
				if hostMountPrefix != "" {
					mountpoint = filepath.Join(hostMountPrefix, partition.Mountpoint)
				}
				diskUsage := tt.du
				diskUsage.Path = mountpoint
				diskUsage.Fstype = partition.Fstype
				mps.On("PSDiskUsage", mountpoint).Return(&diskUsage, nil)
			}
			mps.On("OSGetenv", "HOST_MOUNT_PREFIX").Return(hostMountPrefix)

			// Setup the plugin and run the test
			var acc testutil.Accumulator
			plugin := &Disk{ps: &mps}
			require.NoError(t, plugin.Gather(&acc))

			actual := acc.GetTelegrafMetrics()
			testutil.RequireMetricsEqual(t, tt.expected, actual, testutil.IgnoreTime(), testutil.SortMetrics())
		})
	}
	os.Clearenv()
}
