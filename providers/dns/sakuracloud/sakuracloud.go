// Package sakuracloud implements a DNS provider for solving the DNS-01 challenge using SakuraCloud DNS.
package sakuracloud

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/hnakamur/sakuraclouddns"
)

var _ challenge.ProviderTimeout = (*DNSProvider)(nil)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
	TTL                int
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	client *sakuraclouddns.Client
	config *Config
	logger *slog.Logger
}

type Option func(*DNSProvider)

func WithSlogLogger(logger *slog.Logger) Option {
	return func(p *DNSProvider) {
		p.logger = logger
	}
}

// NewDNSProvider return a DNSProvider instance configured for SakuraCloud.
func NewDNSProvider(client *sakuraclouddns.Client, config *Config, opts ...Option) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("sakuracloud: the configuration of the DNS provider is nil")
	}

	p := &DNSProvider{
		client: client,
		config: config,
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	_ = token
	info := dns01.GetChallengeInfo(domain, keyAuth)

	d.logger.Info("sakuracloud.DNSProvider adding TXT record", "fqdn", info.EffectiveFQDN, "value", info.Value, "ttl", d.config.TTL)
	err := d.addTXTRecord(info.EffectiveFQDN, info.Value, d.config.TTL)
	if err != nil {
		return fmt.Errorf("sakuracloud: %w", err)
	}
	d.logger.Info("sakuracloud.DNSProvider added TXT record", "fqdn", info.EffectiveFQDN, "value", info.Value, "ttl", d.config.TTL)

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	_ = token
	info := dns01.GetChallengeInfo(domain, keyAuth)

	d.logger.Info("sakuracloud.DNSProvider clearing TXT record", "fqdn", info.EffectiveFQDN, "value", info.Value)
	err := d.cleanupTXTRecord(info.EffectiveFQDN, info.Value)
	if err != nil {
		return fmt.Errorf("sakuracloud: %w", err)
	}
	d.logger.Info("sakuracloud.DNSProvider cleared TXT record", "fqdn", info.EffectiveFQDN, "value", info.Value)

	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

func (d *DNSProvider) addTXTRecord(domain string, value string, ttl int) error {
	ctx, cancel := context.WithTimeout(context.Background(), d.config.PropagationTimeout)
	defer cancel()

	zoneName, err := getZoneNameFromDomain(domain)
	if err != nil {
		return err
	}
	subDomain, err := dns01.ExtractSubDomain(domain, zoneName)
	if err != nil {
		return err
	}

	for {
		item, err := d.getRecordsByZoneName(ctx, zoneName)
		if err != nil {
			return err
		}
		records := sakuraclouddns.AddOrUpdateDNSRecordsFunc(
			item.Settings.DNS.ResourceRecordSets,
			isTargetTXTRecord(subDomain, value),
			sakuraclouddns.DNSRecord{Name: subDomain, Type: "TXT", RData: value, TTL: ttl},
		)
		if _, err := d.client.SetRecordsInOneZone(ctx, item.ID, records, item.SettingsHash); err != nil {
			var apiErr *sakuraclouddns.APIError
			if errors.As(err, &apiErr) &&
				apiErr.Reason == sakuraclouddns.APIErrorReasonUnexpectedStatus &&
				apiErr.StatusCode == http.StatusConflict {
				continue
			}
			return err
		}

		return nil
	}
}

func (d *DNSProvider) cleanupTXTRecord(domain string, value string) error {
	ctx, cancel := context.WithTimeout(context.Background(), d.config.PropagationTimeout)
	defer cancel()

	zoneName, err := getZoneNameFromDomain(domain)
	if err != nil {
		return err
	}
	subDomain, err := dns01.ExtractSubDomain(domain, zoneName)
	if err != nil {
		return err
	}

	for {
		item, err := d.getRecordsByZoneName(ctx, zoneName)
		if err != nil {
			return err
		}
		records := sakuraclouddns.DeleteDNSRecordsFunc(
			item.Settings.DNS.ResourceRecordSets,
			isTargetTXTRecord(subDomain, value),
		)
		if _, err := d.client.SetRecordsInOneZone(ctx, item.ID, records, item.SettingsHash); err != nil {
			var apiErr *sakuraclouddns.APIError
			if errors.As(err, &apiErr) &&
				apiErr.Reason == sakuraclouddns.APIErrorReasonUnexpectedStatus &&
				apiErr.StatusCode == http.StatusConflict {
				continue
			}
			return err
		}

		return nil
	}
}

func isTargetTXTRecord(subDomain, value string) func(r sakuraclouddns.DNSRecord) bool {
	return func(r sakuraclouddns.DNSRecord) bool {
		return r.Name == subDomain && r.Type == "TXT" && r.RData == value
	}
}

func (d *DNSProvider) getRecordsByZoneName(ctx context.Context, zoneName string) (*sakuraclouddns.CommonServiceItem, error) {
	items, err := d.client.GetRecordsByZoneName(ctx, zoneName)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("zone %s not found", zoneName)
	}
	if len(items) > 1 {
		return nil, fmt.Errorf("multiple resources are defined for zone %s", zoneName)
	}
	return &items[0], nil
}

func getZoneNameFromDomain(domain string) (string, error) {
	authZone, err := dns01.FindZoneByFqdn(domain)
	if err != nil {
		return "", fmt.Errorf("could not find zone: %w", err)
	}

	zoneName := dns01.UnFqdn(authZone)
	return zoneName, nil
}
