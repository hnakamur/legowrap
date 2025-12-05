package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"runtime/debug"
	"time"

	"github.com/alecthomas/kong"
	"github.com/getsops/sops/v3/decrypt"
	"github.com/go-acme/lego/v4/certificate"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hnakamur/legowrap"
	"go.yaml.in/yaml/v4"
)

type AppConfig struct {
	Log                     LogConfig            `yaml:"log"`
	DaysBeforeIssueCert     int                  `yaml:"days_before_issue_cert"`
	Lego                    legowrap.Config      `yaml:"lego"`
	SakuraCloudDNS          SakuraCloudDNSConfig `yaml:"sakura_cloud_dns"`
	Certificate             string               `yaml:"certificate"`
	CertificateKey          string               `yaml:"certificate_key"`
	PostCommandShellAndOpts []string             `yaml:"post_command_shell_and_opts"`
	PostCommand             string               `yaml:"post_command"`
}

type CLIContext struct {
	Config string
}

var cli CLI

type CLI struct {
	Config        string           `short:"c" default:"/usr/local/etc/legowrap-sakuraclouddns.yaml" env:"CONFIG_PATH" help:"Config file path"`
	Register      RegisterCmd      `cmd:"" help:"Register Account to Let's Encrypt server."`
	EnsureUpdated EnsureUpdatedCmd `cmd:"" help:"Update the certficate if the expiry date is near."`
	Version       VersionCmd       `cmd:"" help:"Show version and exit"`
}

type RegisterCmd struct {
	Email string `required:"" help:"the email address of the account to register to the Let's Encrypt server."`
}

func (c *RegisterCmd) Run(ctx *CLIContext) error {
	cfg, err := readConfig(ctx.Config)
	if err != nil {
		return err
	}

	logFile, err := openLogFile(&cfg.Log, time.Now())
	if err != nil {
		return err
	}
	defer cleanLogFile(logFile)
	setupSlogDefaultLogger(logFile, cfg.Log.Level)

	accKey, err := generateAccountPrivateKey()
	if err != nil {
		return err
	}
	account := &legowrap.Account{Email: c.Email, PrivateKey: accKey}
	client, err := legowrap.NewClient(&cfg.Lego, account)
	if err != nil {
		return err
	}

	accRes, err := client.RegisterAccount(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	accRessourceJSON, err := json.Marshal(accRes)
	if err != nil {
		return err
	}

	accKeyPem, err := encodeInPEM(accKey)
	if err != nil {
		return err
	}

	cfgAccount := legowrap.AccountConfig{
		Email:        c.Email,
		ResourceJSON: string(accRessourceJSON),
		PrivateKey:   string(accKeyPem),
	}

	cfgAccountJSON, err := json.Marshal(cfgAccount)
	if err != nil {
		return err
	}
	if _, err := os.Stdout.Write(cfgAccountJSON); err != nil {
		return err
	}

	return nil
}

type EnsureUpdatedCmd struct {
	Domain      []string `required:"" help:"domain names"`
	SkipGetCert bool     `help:"whether or not to get current certificate from server at the first domain"`
	SkipRenew   bool     `help:"whether or not to skip renew certificate"`
	SkipNew     bool     `help:"whether or not to skip issue a new certificate instead of renew"`
}

func (c *EnsureUpdatedCmd) Run(ctx *CLIContext) error {
	if len(c.Domain) == 0 {
		return errors.New("please set domain(s) with --domain flag")
	}

	cfg, err := readConfig(ctx.Config)
	if err != nil {
		return err
	}

	logFile, err := openLogFile(&cfg.Log, time.Now())
	if err != nil {
		return err
	}
	defer cleanLogFile(logFile)

	setupSlogDefaultLogger(logFile, cfg.Log.Level)
	legolog.Logger = legowrap.NewLegoSlogAdapter(slog.Default())

	domain := c.Domain[0]
	domains := c.Domain
	slog.Info("ensure-updated start",
		"domains", domains,
		"skipGetCert", c.SkipGetCert,
		"skipRenew", c.SkipRenew,
		"skipNew", c.SkipNew,
	)

	accPrivateKey, err := decodeAccountPrivateKeyPEM([]byte(cfg.Lego.Account.PrivateKey))
	if err != nil {
		return err
	}

	account := &legowrap.Account{Email: cfg.Lego.Account.Email, PrivateKey: accPrivateKey}
	if cfg.Lego.Account.ResourceJSON != "" {
		var resource registration.Resource
		if err := json.Unmarshal([]byte(cfg.Lego.Account.ResourceJSON), &resource); err != nil {
			return err
		}
		account.Registration = &resource
	}
	client, err := legowrap.NewClient(&cfg.Lego, account)
	if err != nil {
		return err
	}

	httpClient := &http.Client{Timeout: cfg.SakuraCloudDNS.HTTPClientTimeout}
	dnsProvider, err := newSakuracloudDNSProvider(httpClient, &cfg.SakuraCloudDNS)
	if err != nil {
		return err
	}
	if err := client.SetDNS01Provider(dnsProvider); err != nil {
		return err
	}

	var res *certificate.Resource

	if !c.SkipGetCert {
		curCerts, err := getUnverifiedTLSCertificateChain(domain, domain)
		if err != nil {
			return err
		}
		if len(curCerts) > 0 {
			curCert := curCerts[0]

			res, err = client.RenewCertificate(domain, domains, curCert, time.Now(), c.SkipRenew)
			if err != nil {
				if errors.Is(err, legowrap.ErrNoRenewal) {
					return nil
				}
				if !legowrap.WasIssuedByAnotherIssuerError(err) &&
					!legowrap.WasIssuedByAnotherAccountError(err) {
					return err
				}

				if !errors.Is(err, legowrap.ErrSkipRenewal) {
					slog.Warn("failed to update the old certificate", "err", err)
				}
			}
		}
	}

	if res == nil {
		if c.SkipNew {
			slog.Info("skip issuing a new certifiate and exit")
			return nil
		}

		slog.Info("try issuing a new certifiate")
		res, err = client.IssueNewCertificate(domains)
		if err != nil {
			return err
		}
	}

	if cfg.Certificate != "" {
		if err := os.WriteFile(cfg.Certificate, res.Certificate, 0o600); err != nil {
			return fmt.Errorf("write certificate file: %s", err)
		}
	}
	if cfg.CertificateKey != "" {
		if err := os.WriteFile(cfg.CertificateKey, res.PrivateKey, 0o600); err != nil {
			return fmt.Errorf("write key file: %s", err)
		}
	}
	if cfg.PostCommand != "" {
		if err := runPostCommand(cfg.PostCommandShellAndOpts, cfg.PostCommand); err != nil {
			return fmt.Errorf("run post command: %s", err)
		}
	}

	return nil
}

func runPostCommand(shellAndOpts []string, command string) error {
	if len(shellAndOpts) == 0 {
		shellAndOpts = []string{"/bin/sh", "-c"}
	}
	opts := append(shellAndOpts[1:], command)
	cmd := exec.Command(shellAndOpts[0], opts...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		slog.Error("post_command failed", "output", string(output), "err", err)
		return err
	}
	slog.Info("post_command finished", "output", string(output))
	return nil
}

func readConfig(filename string) (*AppConfig, error) {
	data, err := decrypt.File(filename, "yaml")
	if err != nil {
		return nil, err
	}
	var cfg AppConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

type VersionCmd struct{}

func (c *VersionCmd) Run(ctx *CLIContext) error {
	fmt.Println(Version())
	return nil
}

func Version() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		return info.Main.Version
	}
	return "(devel)"
}

func main() {
	ctx := kong.Parse(&cli,
		kong.Description("Ensure certificates to be updated using Sakura Cloud DNS"))
	err := ctx.Run(&CLIContext{Config: cli.Config})
	ctx.FatalIfErrorf(err)
}
