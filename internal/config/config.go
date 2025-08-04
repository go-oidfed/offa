package config

import (
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/go-oidfed/lib"
	"github.com/go-oidfed/lib/jwx"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/zachmann/go-utils/duration"
	"gopkg.in/yaml.v3"

	"github.com/go-oidfed/offa/internal/model"
)

var conf *Config

// Get returns the Config
func Get() *Config {
	return conf
}

// Config holds the configuration for this application
type Config struct {
	Server         serverConf     `yaml:"server"`
	Logging        loggingConf    `yaml:"logging"`
	Federation     federationConf `yaml:"federation"`
	Auth           authConf       `yaml:"auth"`
	SessionStorage sessionConf    `yaml:"sessions"`
	Signing        signingConf    `yaml:"signing"`
	DebugAuth      bool           `yaml:"debug_auth"`
}

type signingConf struct {
	KeyStorage string               `yaml:"key_storage"`
	Federation jwx.KeyStorageConfig `yaml:"federation"`
	OIDC       jwx.KeyStorageConfig `yaml:"oidc"`
}

type federationConf struct {
	EntityID       string              `yaml:"entity_id"`
	TrustAnchors   oidfed.TrustAnchors `yaml:"trust_anchors"`
	AuthorityHints []string            `yaml:"authority_hints"`

	Scopes                       []string       `yaml:"scopes"`
	ClientName                   string         `yaml:"client_name"`
	ClientURI                    string         `yaml:"client_uri"`
	DisplayName                  string         `yaml:"display_name"`
	Description                  string         `yaml:"description"`
	Keywords                     []string       `yaml:"keywords"`
	Contacts                     []string       `yaml:"contacts"`
	PolicyURI                    string         `yaml:"policy_uri"`
	TOSURI                       string         `yaml:"tos_uri"`
	InformationURI               string         `yaml:"information_uri"`
	LogoURI                      string         `yaml:"logo_uri"`
	OrganizationName             string         `yaml:"organization_name"`
	OrganizationURI              string         `yaml:"organization_uri"`
	ExtraRPMetadata              map[string]any `yaml:"extra_rp_metadata"`
	ExtraEntityConfigurationData map[string]any `yaml:"extra_entity_configuration_data"`

	ConfigurationLifetime       duration.DurationOption                      `yaml:"configuration_lifetime"`
	KeyStorage                  string                                       `yaml:"key_storage"`
	OnlyAutomaticOPs            bool                                         `yaml:"filter_to_automatic_ops"`
	TrustMarks                  []*oidfed.EntityConfigurationTrustMarkConfig `yaml:"trust_marks"`
	UseResolveEndpoint          bool                                         `yaml:"use_resolve_endpoint"`
	UseEntityCollectionEndpoint bool                                         `yaml:"use_entity_collection_endpoint"`
	EntityCollectionInterval    duration.DurationOption                      `yaml:"entity_collection_interval"`
}

type sessionConf struct {
	TTL             int                                               `yaml:"ttl"`
	RedisAddr       string                                            `yaml:"redis_addr"`
	MemCachedAddr   string                                            `yaml:"memcached_addr"`
	MemCachedClaims map[string]oidfed.SliceOrSingleValue[model.Claim] `yaml:"memcached_claims"`
	CookieName      string                                            `yaml:"cookie_name"`
	CookieDomain    string                                            `yaml:"cookie_domain"`
}

func (c sessionConf) validate() error {
	if c.MemCachedClaims != nil {
		if _, set := c.MemCachedClaims["UserName"]; !set {
			return errors.New("sessions.memcached_claims is set, but no claim for 'UserName' is set")
		}
		if _, set := c.MemCachedClaims["Groups"]; !set {
			return errors.New("sessions.memcached_claims is set, but no claim for 'Groups' is set")
		}
	}
	return nil
}

type authConf []*AuthRule

type AuthRule struct {
	Domain               string                                                                       `yaml:"domain"`
	DomainRegex          string                                                                       `yaml:"domain_regex"`
	DomainPattern        *regexp.Regexp                                                               `yaml:"-"`
	Path                 string                                                                       `yaml:"path"`
	PathRegex            string                                                                       `yaml:"path_regex"`
	PathPattern          *regexp.Regexp                                                               `yaml:"-"`
	Require              oidfed.SliceOrSingleValue[map[model.Claim]oidfed.SliceOrSingleValue[string]] `yaml:"require"`
	ForwardHeaders       map[string]oidfed.SliceOrSingleValue[model.Claim]                            `yaml:"forward_headers"`
	ForwardHeadersPrefix string                                                                       `yaml:"forward_headers_prefix"`
	RedirectStatusCode   int                                                                          `yaml:"redirect_status"`
}

var DefaultForwardHeaders = map[string]oidfed.SliceOrSingleValue[model.Claim]{
	"X-Forwarded-User": {
		"preferred_username",
		"sub",
	},
	"X-Forwarded-Email":    {"email"},
	"X-Forwarded-Provider": {"iss"},
	"X-Forwarded-Subject":  {"sub"},
	"X-Forwarded-Groups": {
		"entitlements",
		"groups",
	},
	"X-Forwarded-Name": {"name"},
}
var DefaultMemCachedClaims = map[string]oidfed.SliceOrSingleValue[model.Claim]{
	"UserName": {
		"preferred_username",
		"sub",
	},
	"Groups":    {"groups"},
	"Email":     {"email"},
	"Name":      {"name"},
	"GivenName": {"given_name"},
	"Provider":  {"iss"},
	"Subject":   {"sub"},
}

func (r *AuthRule) validate() error {
	if r.Domain != "" {
		r.DomainRegex = regexp.QuoteMeta(r.Domain)
	}
	if r.Path != "" {
		r.PathRegex = regexp.QuoteMeta(r.Path)
	}
	if r.Domain == "" {
		return errors.New("domain or domain_regex is required")
	}
	r.DomainPattern = regexp.MustCompile(r.DomainRegex)
	if r.PathRegex != "" {
		r.PathPattern = regexp.MustCompile(r.PathRegex)
	}
	return nil
}

func (c *authConf) validate() error {
	for i, rule := range *c {
		if err := rule.validate(); err != nil {
			return err
		}
		(*c)[i] = rule
	}
	return nil
}

func (c authConf) FindRule(host, path string) *AuthRule {
	for _, rule := range c {
		if rule.DomainPattern.MatchString(host) {
			if rule.PathPattern == nil {
				return rule
			}
			if rule.PathPattern.MatchString(path) {
				return rule
			}
		}
	}
	return nil
}

type serverConf struct {
	Port            int          `yaml:"port"`
	TLS             tlsConf      `yaml:"tls"`
	TrustedProxies  []string     `yaml:"trusted_proxies"`
	TrustedNets     []*net.IPNet `yaml:"-"`
	Paths           pathConf     `yaml:"paths"`
	Secure          bool         `yaml:"-"`
	Basepath        string       `yaml:"-"`
	WebOverwriteDir string       `yaml:"web_overwrite_dir"`
}

type pathConf struct {
	Login       string `yaml:"login"`
	ForwardAuth string `yaml:"forward_auth"`
}

type tlsConf struct {
	Enabled      bool   `yaml:"enabled"`
	RedirectHTTP bool   `yaml:"redirect_http"`
	Cert         string `yaml:"cert"`
	Key          string `yaml:"key"`
}

type loggingConf struct {
	Access   LoggerConf         `yaml:"access"`
	Internal internalLoggerConf `yaml:"internal"`
}

type internalLoggerConf struct {
	LoggerConf `yaml:",inline"`
	Level      string          `yaml:"level"`
	Smart      smartLoggerConf `yaml:"smart"`
}

// LoggerConf holds configuration related to logging
type LoggerConf struct {
	Dir    string `yaml:"dir"`
	StdErr bool   `yaml:"stderr"`
}

type smartLoggerConf struct {
	Enabled bool   `yaml:"enabled"`
	Dir     string `yaml:"dir"`
}

func checkLoggingDirExists(dir string) error {
	if dir != "" && !fileExists(dir) {
		return errors.Errorf("logging directory '%s' does not exist", dir)
	}
	return nil
}

func (c *serverConf) validate() error {
	for _, cidr := range c.TrustedProxies {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return errors.Wrapf(err, "invalid trusted proxy CIDR '%s'", cidr)
		}
		c.TrustedNets = append(c.TrustedNets, ipnet)
	}
	return nil
}

func (log *loggingConf) validate() error {
	if err := checkLoggingDirExists(log.Access.Dir); err != nil {
		return err
	}
	if err := checkLoggingDirExists(log.Internal.Dir); err != nil {
		return err
	}
	if log.Internal.Smart.Enabled {
		if log.Internal.Smart.Dir == "" {
			log.Internal.Smart.Dir = log.Internal.Dir
		}
		if err := checkLoggingDirExists(log.Internal.Smart.Dir); err != nil {
			return err
		}
	}
	return nil
}

var possibleConfigLocations = []string{
	".",
	"config",
	"/config",
	"/offa/config",
	"/offa",
	"/data/config",
	"/data",
	"/etc/offa",
}

func validate() error {
	if conf == nil {
		return errors.New("config not set")
	}
	if err := conf.Logging.validate(); err != nil {
		return err
	}
	if err := conf.Server.validate(); err != nil {
		return err
	}
	if err := conf.Auth.validate(); err != nil {
		return err
	}
	if err := conf.SessionStorage.validate(); err != nil {
		return err
	}
	u, err := url.Parse(conf.Federation.EntityID)
	if err != nil {
		return err
	}
	conf.Server.Secure = u.Scheme == "https"
	conf.Server.Basepath = u.Path
	if conf.Server.Basepath != "" {
		if conf.Server.Basepath[len(conf.Server.Basepath)-1] == '/' {
			conf.Server.Basepath = conf.Server.Basepath[:len(conf.Server.Basepath)-2]
		}
		if conf.Server.Basepath[0] != '/' {
			conf.Server.Basepath = "/" + conf.Server.Basepath
		}
	}
	return nil
}

func MustLoadConfig() {
	data, _ := mustReadConfigFile("config.yaml", possibleConfigLocations)
	conf = &Config{
		Server: serverConf{
			Port: 15661,
			Paths: pathConf{
				Login:       "/login",
				ForwardAuth: "/auth",
			},
		},
		SessionStorage: sessionConf{
			TTL:        3600,
			CookieName: "offa-session",
		},
		Federation: federationConf{
			EntityCollectionInterval: duration.DurationOption(5 * time.Minute),
			ConfigurationLifetime:    duration.DurationOption(24 * time.Hour),
		},
		Signing: signingConf{
			Federation: jwx.KeyStorageConfig{
				Algorithm: "ES512",
				RSAKeyLen: 2048,
				RolloverConf: jwx.RolloverConf{
					Enabled:  false,
					Interval: 600000,
				},
			},
			OIDC: jwx.KeyStorageConfig{
				DefaultAlgorithm: "ES512",
				RSAKeyLen:        2048,
				RolloverConf: jwx.RolloverConf{
					Enabled:  false,
					Interval: 600000,
				},
			},
		},
	}
	if err := yaml.Unmarshal(data, conf); err != nil {
		log.Fatal(err)
	}
	if conf.Federation.KeyStorage != "" {
		log.Warn("federation.key_storage is deprecated; use signing.key_storage instead")
		if conf.Signing.KeyStorage == "" {
			conf.Signing.KeyStorage = conf.Federation.KeyStorage
			oldSigningKeyFileToNewFiles := map[string]string{
				filepath.Join(conf.Federation.KeyStorage, "oidc.signing.key"): filepath.Join(
					conf.Federation.KeyStorage, "oidc_ES512.pem",
				),
				filepath.Join(conf.Federation.KeyStorage, "fed.signing.key"): filepath.Join(
					conf.Federation.KeyStorage, "federation_ES512.pem",
				),
			}
			for oldKF, newKF := range oldSigningKeyFileToNewFiles {
				if fileExists(oldKF) && !fileExists(newKF) {
					os.Rename(oldKF, newKF)
				}
			}
		}
	}
	if conf.Signing.KeyStorage == "" {
		log.Fatal("signing.key_storage must be given")
	}
	d, err := os.Stat(conf.Signing.KeyStorage)
	if err != nil {
		log.Fatal(err)
	}
	if !d.IsDir() {
		log.Fatalf("key_storage '%s' must be a directory", conf.Federation.KeyStorage)
	}
	if conf.Federation.ClientName == "" {
		conf.Federation.ClientName = conf.Federation.DisplayName
	}
	if conf.Federation.DisplayName == "" {
		if conf.Federation.ClientName == "" {
			conf.Federation.ClientName = "OFFA - Openid Federation Forward Auth"
		}
		conf.Federation.DisplayName = conf.Federation.ClientName
	}
	if conf.Federation.LogoURI == "" {
		conf.Federation.LogoURI = conf.Federation.EntityID + "/static/img/offa-text.svg"
	}
	if conf.Signing.Federation.RolloverConf.Interval < conf.Federation.ConfigurationLifetime {
		conf.Signing.Federation.RolloverConf.Interval = conf.Federation.ConfigurationLifetime
	}
	if conf.Signing.OIDC.RolloverConf.Interval < conf.Federation.ConfigurationLifetime {
		conf.Signing.OIDC.RolloverConf.Interval = conf.Federation.ConfigurationLifetime
	}
	if conf.Federation.UseEntityCollectionEndpoint && conf.Federation.EntityCollectionInterval.Duration() < time.Minute {
		log.Fatal("federation.use_entity_collection_interval must be at least 1 minute")
	}
	if err = validate(); err != nil {
		log.Fatalf("%s", err)
	}
}
