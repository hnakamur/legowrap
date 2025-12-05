package main

import (
	"net/http"
	"time"

	"github.com/hnakamur/legowrap/providers/dns/sakuracloud"
	"github.com/hnakamur/sakuraclouddns"
)

type SakuraCloudDNSConfig struct {
	Token              string        `yaml:"token"`
	Secret             string        `yaml:"secret"`
	TTL                int           `yaml:"ttl"`
	PropagationTimeout time.Duration `yaml:"propagation_timeout"`
	PollingInterval    time.Duration `yaml:"polling_interval"`
	HTTPClientTimeout  time.Duration `yaml:"http_client_timeout"`
}

func newSakuracloudDNSProvider(httpClient *http.Client, cfg *SakuraCloudDNSConfig) (*sakuracloud.DNSProvider, error) {
	dnsAPIClient, err := sakuraclouddns.NewClient(httpClient,
		cfg.Token,
		cfg.Secret,
	)
	if err != nil {
		return nil, err
	}

	return sakuracloud.NewDNSProvider(dnsAPIClient, &sakuracloud.Config{
		PropagationTimeout: cfg.PropagationTimeout,
		PollingInterval:    cfg.PollingInterval,
		TTL:                cfg.TTL,
	})
}
