package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/hnakamur/ghesmanage"
)

type GHESManageConfig struct {
	ApplyWaitInterval time.Duration              `yaml:"apply_wait_interval"`
	HTTPClient        GHESManageHTTPClientConfig `yaml:"http_client"`
	HTTPAuth          GHESManageHTTPAuthConfig   `yaml:"http_auth"`
}

type GHESManageHTTPClientConfig struct {
	Timeout       time.Duration `yaml:"timeout"`
	TLSSkipVerify bool          `yaml:"tls_skip_verify"`
}

type GHESManageHTTPAuthConfig struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

const (
	managementEndpointScheme = "https"
	managementEndpointPort   = "8443"
	managementEndpointPath   = "/manage"
)

func updateAndWaitGHESCertificateAndKey(ctx context.Context, domain string, cfg *GHESManageConfig, cert, key string) error {
	httpClient := &http.Client{Timeout: cfg.HTTPClient.Timeout}
	if cfg.HTTPClient.TLSSkipVerify {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig.InsecureSkipVerify = true
		httpClient.Transport = tr
		slog.Debug("enabled httpClient TLSClientConfig.InsecureSkipVerify")
	}

	managementEndpoint := (&url.URL{
		Scheme: managementEndpointScheme,
		Host:   net.JoinHostPort(domain, managementEndpointPort),
		Path:   managementEndpointPath,
	}).String()

	apiClient, err := ghesmanage.NewAPIClient(httpClient, managementEndpoint, cfg.HTTPAuth.User, cfg.HTTPAuth.Password)
	if err != nil {
		return err
	}

	slog.Info("setting certificate and key", "endpoint", managementEndpoint)
	if err := apiClient.SetCertificateAndKey(ctx, cert, key); err != nil {
		return err
	}

	startTime := time.Now()
	runID := "cert_update_" + startTime.Format("20060102150405")
	slog.Info("applying the change of certificate and key...", "run_id", runID)
	if _, err := apiClient.TriggerConfigApply(ctx, runID); err != nil {
		return err
	}

	for {
		status, err := apiClient.GetConfigApplyStatus(ctx, runID)
		if err != nil {
			return err
		}
		if !status.Running {
			if !status.Successful {
				return errors.New("failed to apply change of certificate and key")
			}
			slog.Info("finished setting certificate and key", "elapsed", time.Since(startTime).String())
			return nil
		}

		slog.Info("waiting for the change to be applied",
			"status", status,
			"apply_wait_interval", cfg.ApplyWaitInterval.String())

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(cfg.ApplyWaitInterval):
		}
	}
}
