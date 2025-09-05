package legowrap

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hashicorp/go-retryablehttp"
)

type Client struct {
	legoClient *lego.Client
	config     *Config
	logger     *slog.Logger
}

type Config struct {
	CADirURL    string            `yaml:"ca_dir_url"`
	UserAgent   string            `yaml:"user_agent"`
	Account     AccountConfig     `yaml:"account"`
	Certificate CertificateConfig `yaml:"certificate"`
	HTTPClient  HTTPClientConfig  `yaml:"http_client"`
	DNS         DNSConfig         `yaml:"dns"`
	ARI         ARIConfig         `yaml:"ari"`
	Renew       RenewConfig       `yaml:"renew"`
}

type AccountConfig struct {
	Email        string `yaml:"email" json:"email"`
	ResourceJSON string `yaml:"resource_json" json:"resource_json"`
	PrivateKey   string `yaml:"private_key" json:"private_key"`
}

type CertificateConfig struct {
	Timeout             time.Duration                  `yaml:"cert_timeout"`
	OverallRequestLimit int                            `yaml:"overall_request_limit"`
	DisableCommonName   bool                           `yaml:"disable_common_name"`
	ObtainRequest       CertificateObtainRequestConfig `yaml:"obtain_request"`
}

type CertificateObtainRequestConfig struct {
	MustStaple                     bool   `yaml:"must_staple"`
	Bundle                         bool   `yaml:"bundle"`
	PreferredChain                 string `yaml:"preferred_chain"`
	Profile                        string `yaml:"profile"`
	AlwaysDeactivateAuthorizations bool   `yaml:"always_deactivate_authorizations"`
}

type HTTPClientConfig struct {
	Timeout       time.Duration `yaml:"timeout"`
	TLSSkipVerify bool          `yaml:"tls_skip_verify"`
}

type DNSConfig struct {
	Timeout               time.Duration `yaml:"timeout"`
	Resolvers             []string      `yaml:"resolvers"`
	DisableCP             bool          `yaml:"disable_cp"`
	PropagationDisableANS bool          `yaml:"propagation_disable_ans"`
	PropagationRNS        bool          `yaml:"propagation_rns"`
	PropagationWait       time.Duration `yaml:"propagation_wait"`
}

type ARIConfig struct {
	Disable             bool          `yaml:"disable"`
	WaitToRenewDuration time.Duration `yaml:"wait_to_renew_duration"`
}

type RenewConfig struct {
	Days    int  `yaml:"days"`
	Dynamic bool `yaml:"dynamic"`
}

var ErrNoRenewal = errors.New("no renewal")
var ErrCetificateBundleStartsWithCA = errors.New("certificate bundle starts with a CA certificate")

type Option func(*Client)

func WithSlogLogger(logger *slog.Logger) Option {
	return func(c *Client) {
		c.logger = logger
	}
}

func NewClient(cfg *Config, acc registration.User, keyType certcrypto.KeyType, opts ...Option) (*Client, error) {
	c := &Client{
		config: cfg,
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(c)
	}

	config := lego.NewConfig(acc)
	config.CADirURL = cfg.CADirURL
	config.UserAgent = cfg.UserAgent

	config.Certificate = lego.CertificateConfig{
		KeyType:             keyType,
		Timeout:             cfg.Certificate.Timeout,
		OverallRequestLimit: cfg.Certificate.OverallRequestLimit,
		DisableCommonName:   cfg.Certificate.DisableCommonName,
	}

	if cfg.HTTPClient.Timeout != 0 {
		config.HTTPClient.Timeout = cfg.HTTPClient.Timeout
	}

	if cfg.HTTPClient.TLSSkipVerify {
		defaultTransport, ok := config.HTTPClient.Transport.(*http.Transport)
		if ok { // This is always true because the default client used by the CLI defined the transport.
			tr := defaultTransport.Clone()
			tr.TLSClientConfig.InsecureSkipVerify = true
			config.HTTPClient.Transport = tr
		}
	}

	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 5
	retryClient.HTTPClient = config.HTTPClient
	retryClient.Logger = c.logger

	config.HTTPClient = retryClient.StandardClient()

	legoClient, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("could not create client: %v", err)
	}
	c.legoClient = legoClient

	// if client.GetExternalAccountRequired() && !ctx.IsSet(flgEAB) {
	// 	log.Fatalf("Server requires External Account Binding. Use --%s with --%s and --%s.", flgEAB, flgKID, flgHMAC)
	// }

	return c, nil
}

func (c *Client) RegisterAccount(opts registration.RegisterOptions) (*registration.Resource, error) {
	return c.legoClient.Registration.Register(opts)
}

func (c *Client) SetDNS01Provider(dnsProvider challenge.Provider) error {
	err := c.legoClient.Challenge.SetDNS01Provider(dnsProvider,
		dns01.CondOption(len(c.config.DNS.Resolvers) > 0,
			dns01.AddRecursiveNameservers(dns01.ParseNameservers(c.config.DNS.Resolvers))),

		dns01.CondOption(c.config.DNS.DisableCP || c.config.DNS.PropagationDisableANS,
			dns01.DisableAuthoritativeNssPropagationRequirement()),

		dns01.CondOption(c.config.DNS.PropagationWait > 0,
			// TODO(ldez): inside the next major version we will use flgDNSDisableCP here.
			// This will change the meaning of this flag to really disable all propagation checks.
			dns01.PropagationWait(c.config.DNS.PropagationWait, true)),

		dns01.CondOption(c.config.DNS.PropagationRNS,
			dns01.RecursiveNSsPropagationRequirement()),

		dns01.CondOption(c.config.DNS.Timeout > 0,
			dns01.AddDNSTimeout(c.config.DNS.Timeout)),
	)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) IssueNewCertificate(domains []string) (*certificate.Resource, error) {
	reqCfg := &c.config.Certificate.ObtainRequest
	request := certificate.ObtainRequest{
		Domains:                        domains,
		MustStaple:                     reqCfg.MustStaple,
		Bundle:                         reqCfg.Bundle,
		PreferredChain:                 reqCfg.PreferredChain,
		Profile:                        reqCfg.Profile,
		AlwaysDeactivateAuthorizations: reqCfg.AlwaysDeactivateAuthorizations,
	}
	return c.legoClient.Certificate.Obtain(request)
}

func (c *Client) RenewCertificate(domain string, domains []string,
	curCert *x509.Certificate, now time.Time) (*certificate.Resource, error) {

	var ariRenewalTime *time.Time
	var replacesCertID string

	if !c.config.ARI.Disable {
		now = now.UTC()
		var err error
		ariRenewalTime, err = c.getARIRenewalTime(curCert, domain, now)
		if err != nil {
			return nil, err
		}
		c.logger.Info("after getARIRenewalTime", "ariRenewalTime", ariRenewalTime)
		if ariRenewalTime != nil {
			// Figure out if we need to sleep before renewing.
			if ariRenewalTime.After(now) {
				dur := ariRenewalTime.Sub(now)
				c.logger.Info("Sleeping until renewal time", "domain",
					domain, "duration", dur, "ariRenewalTime", ariRenewalTime)
				time.Sleep(dur)
			}
		}

		replacesCertID, err = certificate.MakeARICertID(curCert)
		if err != nil {
			return nil,
				fmt.Errorf("error while construction the ARI CertID for domain %s, err: %v",
					domain, err)
		}
		c.logger.Info("got replacesCertID", "replacesCertID", replacesCertID)
	}

	if ariRenewalTime == nil {
		if err := c.needRenewal(curCert, domain, c.config.Renew.Days, c.config.Renew.Dynamic, now); err != nil {
			return nil, err
		}
	}

	reqCfg := &c.config.Certificate.ObtainRequest
	request := certificate.ObtainRequest{
		Domains:                        domains,
		MustStaple:                     reqCfg.MustStaple,
		Bundle:                         reqCfg.Bundle,
		PreferredChain:                 reqCfg.PreferredChain,
		Profile:                        reqCfg.Profile,
		AlwaysDeactivateAuthorizations: reqCfg.AlwaysDeactivateAuthorizations,
		ReplacesCertID:                 replacesCertID,
	}

	return c.legoClient.Certificate.Obtain(request)
}

// getARIRenewalTime checks if the certificate needs to be renewed using the renewalInfo endpoint.
func (c *Client) getARIRenewalTime(cert *x509.Certificate, domain string,
	now time.Time) (*time.Time, error) {

	if cert.IsCA {
		c.logger.Error("Certificate bundle starts with a CA certificate", "domain", domain)
		return nil, ErrCetificateBundleStartsWithCA
	}

	renewalInfo, err := c.legoClient.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: cert})
	if err != nil {
		if errors.Is(err, api.ErrNoARI) {
			c.logger.Warn("The server does not advertise a renewal info endpoint", "domain", domain, "err", err)
			return nil, nil
		}
		c.logger.Warn("acme: calling renewal info endpoint", "domain", domain, "err", err)
		return nil, nil
	}

	renewalTime := renewalInfo.ShouldRenewAt(now, c.config.ARI.WaitToRenewDuration)
	if renewalTime == nil {
		c.logger.Info("acme: renewalInfo endpoint indicates that renewal is not needed", "domain", domain)
		return nil, nil
	}
	c.logger.Info("acme: renewalInfo endpoint indicates that renewal is needed", "domain", domain)

	if renewalInfo.ExplanationURL != "" {
		c.logger.Info("acme: renewalInfo endpoint provided an explanation",
			"domain", domain, "renewalInfo.ExpranationURL", renewalInfo.ExplanationURL)
	}

	return renewalTime, nil
}

func WasIssuedByAnotherIssuerError(err error) bool {
	return err.Error() ==
		"acme: error: 404 :: POST :: https://acme-staging-v02.api.letsencrypt.org/acme/new-order :: "+
			"urn:ietf:params:acme:error:malformed :: Could not validate ARI 'replaces' field :: "+
			"path contained an Authority Key Identifier that did not match a known issuer"
}

func WasIssuedByAnotherAccountError(err error) bool {
	return err.Error() ==
		"acme: error: 403 :: POST :: https://acme-v02.api.letsencrypt.org/acme/new-order :: "+
			"urn:ietf:params:acme:error:unauthorized :: Could not validate ARI 'replaces' field :: "+
			"requester account did not request the certificate being replaced by this order"
}

func (c *Client) needRenewal(x509Cert *x509.Certificate, domain string, days int, dynamic bool, now time.Time) error {
	if x509Cert.IsCA {
		c.logger.Error("Certificate bundle starts with a CA certificate", "domain", domain)
		return ErrCetificateBundleStartsWithCA
	}

	if dynamic {
		return c.needRenewalDynamic(x509Cert, domain, now)
	}

	notAfter := int(x509Cert.NotAfter.Sub(now).Hours() / 24.0)

	c.logger.Info("needRenewal nonDynamic",
		"domain", domain, "definedRenewwalDays", days,
		"certNotAfter", x509Cert.NotAfter.Format(time.RFC3339),
		"now", now.Format(time.RFC3339),
		"notAfterInDays", notAfter)

	if days < 0 {
		return nil
	}

	if notAfter <= days {
		return nil
	}

	c.logger.Info("no renewal.",
		"domain", domain, "expiresInDays", notAfter, "definedRenewwalDays", days)

	return ErrNoRenewal
}

func (c *Client) needRenewalDynamic(x509Cert *x509.Certificate, domain string, now time.Time) error {
	lifetime := x509Cert.NotAfter.Sub(x509Cert.NotBefore)

	var divisor int64 = 3
	if lifetime.Round(24*time.Hour).Hours()/24.0 <= 10 {
		divisor = 2
	}

	dueDate := x509Cert.NotAfter.Add(-1 * time.Duration(lifetime.Nanoseconds()/divisor))

	c.logger.Info("needRenewal dynamic",
		"domain", domain,
		"certNotAfter", x509Cert.NotAfter.Format(time.RFC3339),
		"now", now.Format(time.RFC3339),
		"dueDate", dueDate.Format(time.RFC3339))

	if dueDate.Before(now) {
		return nil
	}

	c.logger.Info("no renewal for dynamic",
		"domain", domain,
		"expiryDate", x509Cert.NotAfter.Format(time.RFC3339),
		"renewalCanBePerfomedIn", dueDate.Sub(now).String())

	return ErrNoRenewal
}
