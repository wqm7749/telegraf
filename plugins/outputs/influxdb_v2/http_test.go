package influxdb_v2

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/internal"
	"github.com/influxdata/telegraf/metric"
	"github.com/influxdata/telegraf/plugins/common/ratelimiter"
	"github.com/influxdata/telegraf/plugins/serializers/influx"
	"github.com/influxdata/telegraf/testutil"
)

func TestHTTPClientInit(t *testing.T) {
	tests := []struct {
		name   string
		addr   string
		client *httpClient
	}{
		{
			name:   "unix socket",
			addr:   "unix://var/run/influxd.sock",
			client: &httpClient{},
		},
		{
			name: "unix socket with timeouts",
			addr: "unix://var/run/influxd.sock",
			client: &httpClient{
				pingTimeout:     config.Duration(15 * time.Second),
				readIdleTimeout: config.Duration(30 * time.Second),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.addr)
			require.NoError(t, err)
			tt.client.url = u

			require.NoError(t, tt.client.Init())
		})
	}
}

func TestHTTPClientInitFail(t *testing.T) {
	tests := []struct {
		name   string
		addr   string
		client *httpClient
	}{
		{
			name:   "udp unsupported",
			addr:   "udp://localhost:9999",
			client: &httpClient{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.addr)
			require.NoError(t, err)
			tt.client.url = u

			require.Error(t, tt.client.Init())
		})
	}
}

func TestMakeWriteURL(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected string
		bucket   string
		org      string
	}{
		{
			name:     "http default",
			addr:     "http://localhost:9999",
			expected: "http://localhost:9999/api/v2/write?bucket=telegraf0&org=influx0",
			bucket:   "telegraf0",
			org:      "influx0",
		},
		{
			name:     "http with param",
			addr:     "http://localhost:9999?id=abc",
			expected: "http://localhost:9999/api/v2/write?bucket=telegraf1&id=abc&org=influx1",
			bucket:   "telegraf1",
			org:      "influx1",
		},
		{
			name:     "unix socket default",
			addr:     "unix://var/run/influxd.sock",
			expected: "http://127.0.0.1/api/v2/write?bucket=telegraf2&org=influx2",
			bucket:   "telegraf2",
			org:      "influx2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.addr)
			require.NoError(t, err)

			preppedURL, params, err := prepareWriteURL(*u, tt.org)
			require.NoError(t, err)
			require.Equal(t, tt.expected, makeWriteURL(*preppedURL, params, tt.bucket))
		})
	}
}

func TestMakeWriteURLFail(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected string
		bucket   string
		org      string
	}{
		{
			name: "default values",
			addr: "udp://localhost:9999",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.addr)
			require.NoError(t, err)

			_, _, err = prepareWriteURL(*u, tt.org)
			require.Error(t, err)
		})
	}
}

func TestExponentialBackoffCalculation(t *testing.T) {
	tests := []struct {
		retryCount int64
		expected   time.Duration
	}{
		{retryCount: 0, expected: 0},
		{retryCount: 1, expected: 25 * time.Millisecond},
		{retryCount: 5, expected: 625 * time.Millisecond},
		{retryCount: 10, expected: 2500 * time.Millisecond},
		{retryCount: 30, expected: 22500 * time.Millisecond},
		{retryCount: 40, expected: 40 * time.Second},
		{retryCount: 50, expected: 60 * time.Second}, // max hit
		{retryCount: 100, expected: 60 * time.Second},
		{retryCount: 1000, expected: 60 * time.Second},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%d_retries", test.retryCount), func(t *testing.T) {
			require.EqualValues(t, test.expected, getRetryDuration(http.Header{}, test.retryCount))
		})
	}
}

func TestExponentialBackoffCalculationWithRetryAfter(t *testing.T) {
	tests := []struct {
		retryCount int64
		retryAfter string
		expected   time.Duration
	}{
		{retryCount: 0, retryAfter: "0", expected: 0},
		{retryCount: 0, retryAfter: "10", expected: 10 * time.Second},
		{retryCount: 0, retryAfter: "60", expected: 60 * time.Second},
		{retryCount: 0, retryAfter: "600", expected: 600 * time.Second},
		{retryCount: 0, retryAfter: "601", expected: 600 * time.Second}, // max hit
		{retryCount: 40, retryAfter: "39", expected: 40 * time.Second},  // retryCount wins
		{retryCount: 40, retryAfter: "41", expected: 41 * time.Second},  // retryAfter wins
		{retryCount: 100, retryAfter: "100", expected: 100 * time.Second},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%d_retries", test.retryCount), func(t *testing.T) {
			hdr := http.Header{}
			hdr.Add("Retry-After", test.retryAfter)
			require.EqualValues(t, test.expected, getRetryDuration(hdr, test.retryCount))
		})
	}
}

func TestRetryLaterEarlyExit(t *testing.T) {
	var received atomic.Int64

	// Setup a test server
	ts := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			received.Add(1)
			w.Header().Add("Retry-After", "120")
			w.WriteHeader(http.StatusTooManyRequests)
		}),
	)
	defer ts.Close()

	// Prepare the serializer etc
	serializer := &influx.Serializer{}
	require.NoError(t, serializer.Init())
	var limiterCfg ratelimiter.RateLimitConfig
	limiter, err := limiterCfg.CreateRateLimiter()
	require.NoError(t, err)

	// Setup client
	u, err := url.Parse("http://" + ts.Listener.Addr().String())
	require.NoError(t, err)

	c := &httpClient{
		url:             u,
		bucketTag:       "bucket",
		contentEncoding: "identity",
		serializer:      ratelimiter.NewIndividualSerializer(serializer),
		rateLimiter:     limiter,
		log:             &testutil.Logger{},
	}
	require.NoError(t, c.Init())

	// Together the metric batch size is too big, split up, we get success
	metrics := []telegraf.Metric{
		metric.New(
			"cpu",
			map[string]string{
				"bucket": "foo",
			},
			map[string]interface{}{
				"value": 0.0,
			},
			time.Unix(0, 0),
		),
		metric.New(
			"cpu",
			map[string]string{
				"bucket": "my_bucket",
			},
			map[string]interface{}{
				"value": 42.0,
			},
			time.Unix(0, 1),
		),
		metric.New(
			"cpu",
			map[string]string{
				"bucket": "my_bucket",
			},
			map[string]interface{}{
				"value": 43.0,
			},
			time.Unix(0, 2),
		),
		metric.New(
			"cpu",
			map[string]string{
				"bucket": "foo",
			},
			map[string]interface{}{
				"value": 0.0,
			},
			time.Unix(0, 3),
		),
	}

	// Write the metrics the first time and check for the expected errors
	err = c.Write(t.Context(), metrics)
	require.ErrorContains(t, err, "waiting 2m0s for server before sending metrics again")

	var writeErr *internal.PartialWriteError
	require.ErrorAs(t, err, &writeErr)
	require.Empty(t, writeErr.MetricsReject, "rejected metrics")
	require.LessOrEqual(t, len(writeErr.MetricsAccept), 2, "accepted metrics")
	require.InDelta(t, 120*time.Second, time.Until(c.retryTime), float64(time.Second))
	require.EqualValues(t, int64(1), received.Load(), "unexpected number of posts")
}

func TestHeadersDoNotOverrideConfig(t *testing.T) {
	testURL, err := url.Parse("https://localhost:8181")
	require.NoError(t, err)
	authHeader := config.NewSecret([]byte("Bearer foo"))
	userAgentHeader := config.NewSecret([]byte("foo"))
	c := &httpClient{
		headers: map[string]*config.Secret{
			"Authorization": &authHeader,
			"User-Agent":    &userAgentHeader,
		},
		// URL to make Init() happy
		url: testURL,
	}
	require.NoError(t, c.Init())
	require.Equal(t, &authHeader, c.headers["Authorization"])
	require.Equal(t, &userAgentHeader, c.headers["User-Agent"])
}

// goos: linux
// goarch: amd64
// pkg: github.com/influxdata/telegraf/plugins/outputs/influxdb_v2
// cpu: 11th Gen Intel(R) Core(TM) i7-11850H @ 2.50GHz
// BenchmarkOldMakeWriteURL
// BenchmarkOldMakeWriteURL-16    	 1556631	       683.2 ns/op	     424 B/op	      14 allocs/op
// PASS
// ok  	github.com/influxdata/telegraf/plugins/outputs/influxdb_v2	1.851s
func BenchmarkOldMakeWriteURL(b *testing.B) {
	org := "org"

	u, err := url.Parse("http://localhost:8086")
	require.NoError(b, err)
	loc, _, err := prepareWriteURL(*u, org)
	require.NoError(b, err)

	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		//nolint:errcheck // Skip error for benchmarking
		oldMakeWriteURL(*loc)
	}
}

// goos: linux
// goarch: amd64
// pkg: github.com/influxdata/telegraf/plugins/outputs/influxdb_v2
// cpu: 11th Gen Intel(R) Core(TM) i7-11850H @ 2.50GHz
// BenchmarkNewMakeWriteURL
// BenchmarkNewMakeWriteURL-16    	 2084415	       496.5 ns/op	     280 B/op	       9 allocs/op
// PASS
// ok  	github.com/influxdata/telegraf/plugins/outputs/influxdb_v2	1.626s
func BenchmarkNewMakeWriteURL(b *testing.B) {
	bucket := "bkt"
	org := "org"

	u, err := url.Parse("http://localhost:8086")
	require.NoError(b, err)
	loc, params, err := prepareWriteURL(*u, org)
	require.NoError(b, err)

	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		makeWriteURL(*loc, params, bucket)
	}
}

func oldMakeWriteURL(loc url.URL) (string, error) {
	params := url.Values{}
	params.Set("bucket", "bkt")
	params.Set("org", "org")

	switch loc.Scheme {
	case "unix":
		loc.Scheme = "http"
		loc.Host = "127.0.0.1"
		loc.Path = "/api/v2/write"
	case "http", "https":
		loc.Path = path.Join(loc.Path, "/api/v2/write")
	default:
		return "", fmt.Errorf("unsupported scheme: %q", loc.Scheme)
	}
	loc.RawQuery = params.Encode()
	return loc.String(), nil
}
