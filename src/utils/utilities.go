package utils

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"

	pb "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/golang/protobuf/ptypes/duration"
	logger "github.com/sirupsen/logrus"
)

// Interface for a time source.
type TimeSource interface {
	// @return the current unix time in seconds.
	UnixNow() int64
}

// Convert a rate limit into a time divider.
// @param unit supplies the unit to convert.
// @return the divider to use in time computations.
func UnitToDivider(unit pb.RateLimitResponse_RateLimit_Unit) int64 {
	switch unit {
	case pb.RateLimitResponse_RateLimit_SECOND:
		return 1
	case pb.RateLimitResponse_RateLimit_MINUTE:
		return 60
	case pb.RateLimitResponse_RateLimit_HOUR:
		return 60 * 60
	case pb.RateLimitResponse_RateLimit_DAY:
		return 60 * 60 * 24
	}

	panic("should not get here")
}

func CalculateReset(currentLimit *pb.RateLimitResponse_RateLimit, timeSource TimeSource) *duration.Duration {
	sec := UnitToDivider(currentLimit.Unit)
	now := timeSource.UnixNow()
	return &duration.Duration{Seconds: sec - now%sec}
}

func Max(a uint32, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func GenerateTlsConfig(redisTlsCACerts string) (*tls.Config, error) {
	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	// Read in the cert file
	certs, err := ioutil.ReadFile(redisTlsCACerts)
	if err != nil {
		return nil, err
	}

	// Append our cert to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		logger.Warnf("No certs appended, using system certs only")
	}

	// Trust the augmented cert pool in our client
	return &tls.Config{
		RootCAs: rootCAs,
	}, nil
}
