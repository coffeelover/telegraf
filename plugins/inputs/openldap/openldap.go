package openldap

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/common/tls"
	"github.com/influxdata/telegraf/plugins/inputs"
	"gopkg.in/ldap.v3"
)

type Openldap struct {
	Host               string // Deprecated; use URI
	Port               int    // Deprecated; use URI
	SSL                string `toml:"ssl"` // Deprecated in 1.7; use TLS
	TLS                string `toml:"tls"`
	URI                string `toml:"uri"`
	BindDn             string `toml:"bind_dn"`
	BindPassword       string `toml:"bind_password"`
	ReverseMetricNames bool   `toml:"reverse_metric_names"`
	tls.ClientConfig
}

const sampleConfig string = `
  ## LDAP url used for connection
  ## format: uri = "<scheme>://><hostname>:<port>
  ## scheme: either ldapi, ldaps, ldap
  ##         default is ldapi
  ## hostname: ip address or hostname for tcp connection (ldap, ldaps)
               path for ldapi (or '/' for compile default)
               (no need to escape path separators)
  ## port: optional (default is 389 for ldap, 636 for ldaps)
  ## example: uri = ldapi:///
  ##          uri = ldapi://run/slapd/ldapi
  ##          uri = ldap://ldap.example.com
  ##          uri = ldaps://ldap.example.com
  ##          uri = ldaps://ldap.example.com:8636
  uri = "ldapi:///"

  # use starttls on ldap port (only valid for ldap scheme)
  # either true/starttls or false
  # default: false
  tls = false

  # skip peer certificate verification. Default is false.
  insecure_skip_verify = false

  # Path to PEM-encoded Root certificate to use to verify server certificate
  tls_ca = "/etc/ssl/certs.pem"

  # dn/password to bind with. If bind_dn is empty, an anonymous bind is performed.
  # when using ldapi schema, external bind is done automatically.
  bind_dn = ""
  bind_password = ""

  # Reverse metric names so they sort more naturally. Recommended.
  # This defaults to false if unset, but is set to true when generating a new config
  reverse_metric_names = true
`

var searchBase = "cn=Monitor"
var searchFilter = "(|(objectClass=monitorCounterObject)(objectClass=monitorOperation)(objectClass=monitoredObject))"
var searchAttrs = []string{"monitorCounter", "monitorOpInitiated", "monitorOpCompleted", "monitoredInfo"}
var attrTranslate = map[string]string{
	"monitorCounter":     "",
	"monitoredInfo":      "",
	"monitorOpInitiated": "_initiated",
	"monitorOpCompleted": "_completed",
	"olmMDBPagesMax":     "_mdb_pages_max",
	"olmMDBPagesUsed":    "_mdb_pages_used",
	"olmMDBPagesFree":    "_mdb_pages_free",
	"olmMDBReadersMax":   "_mdb_readers_max",
	"olmMDBReadersUsed":  "_mdb_readers_used",
	"olmMDBEntries":      "_mdb_entries",
}

func (o *Openldap) SampleConfig() string {
	return sampleConfig
}

func (o *Openldap) Description() string {
	return "OpenLDAP cn=Monitor plugin"
}

// return an initialized Openldap
func NewOpenldap() *Openldap {
	return &Openldap{
		URI: "ldap://localhost",
	}
}

// gather metrics
func (o *Openldap) Gather(acc telegraf.Accumulator) error {
	var err error
	var l *ldap.Conn

	if o.Host != "" {
		scheme := "ldap"
		if o.URI != "" {
			acc.AddError(fmt.Errorf("Both uri and host are specified in config, cannot continue!"))
			return nil
		}

		if o.SSL != "" {
			if o.TLS != "" {
				acc.AddError(fmt.Errorf("Both TLS and SSL are specified in config, cannot continue!"))
				return nil
			} else {
				o.TLS = o.SSL
			}
		}
		if o.TLS != "" {
			switch o.TLS {
			case "yes",
				"true",
				"on",
				"ssl":
				scheme = "ldaps"
			}
		}
		if o.Port == 0 {
			if scheme == "ldap" {
				o.Port, err = strconv.Atoi(ldap.DefaultLdapPort)
			} else {
				o.Port, err = strconv.Atoi(ldap.DefaultLdapsPort)
			}
		}
		o.URI = fmt.Sprintf("%s://%s:%d", scheme, o.Host, o.Port)
	}

	u, err := url.Parse(o.URI)
	if err != nil {
		acc.AddError(err)
		return nil
	}

	tlsCfg, err := o.ClientConfig.TLSConfig()
	if err != nil {
		acc.AddError(err)
		return nil
	}

	switch u.Scheme {
	case "ldapi":
		l, err = ldap.Dial("unix", u.Path)
		if err != nil {
			acc.AddError(err)
			return nil
		}
		err = l.ExternalBind()
		if err != nil {
			acc.AddError(err)
			return nil
		}
	case "ldaps":
		host, port, err := net.SplitHostPort(u.Host)
		if err != nil {
			// we asume that error is due to missing port
			host = u.Host
			port = ldap.DefaultLdapsPort
		}

		l, err = ldap.DialTLS("tcp", net.JoinHostPort(host, port), tlsCfg)
		if err != nil {
			acc.AddError(err)
			return nil
		}
		if o.BindDn != "" && o.BindPassword != "" {
			err = l.Bind(o.BindDn, o.BindPassword)
			if err != nil {
				acc.AddError(err)
				return nil
			}
		}
	case "ldap":
		start_tls := false
		l, err = ldap.DialURL(o.URI)
		if err != nil {
			acc.AddError(err)
			return nil
		}
		// Check for STARTTLS
		if o.SSL != "" {
			o.TLS = o.SSL
		}

		switch o.TLS {
		case
			"yes",
			"true",
			"on",
			"ssl",
			"starttls":
			start_tls = true
		}
		if start_tls {
			err = l.StartTLS(tlsCfg)
			if err != nil {
				acc.AddError(err)
				return nil
			}
		}
		if o.BindDn != "" && o.BindPassword != "" {
			err = l.Bind(o.BindDn, o.BindPassword)
			if err != nil {
				acc.AddError(err)
				return nil
			}
		}
	}

	defer l.Close()

	searchRequest := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		searchFilter,
		searchAttrs,
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		acc.AddError(err)
		return nil
	}

	gatherSearchResult(sr, o, acc)

	return nil
}

func gatherSearchResult(sr *ldap.SearchResult, o *Openldap, acc telegraf.Accumulator) error {
	fields := map[string]interface{}{}
	u, err := url.Parse(o.URI)
	if err != nil {
		return fmt.Errorf("Unable to parse LDAP uri '%s'", o.URI)
	}
	tags := map[string]string{
		"server": u.Hostname(),
		"port":   u.Port(),
	}
	for _, entry := range sr.Entries {
		metricName := dnToMetric(entry.DN, o)
		for _, attr := range entry.Attributes {
			if len(attr.Values[0]) >= 1 {
				if v, err := strconv.ParseInt(attr.Values[0], 10, 64); err == nil {
					fields[metricName+attrTranslate[attr.Name]] = v
				}
			}
		}
	}
	acc.AddFields("openldap", fields, tags)
	return nil
}

// Convert a DN to metric name, eg cn=Read,cn=Waiters,cn=Monitor becomes waiters_read
// Assumes the last part of the DN is cn=Monitor and we want to drop it
func dnToMetric(dn string, o *Openldap) string {
	if o.ReverseMetricNames {
		var metricParts []string

		dn = strings.Trim(dn, " ")
		dn = strings.Replace(dn, " ", "_", -1)
		dn = strings.Replace(dn, "cn=", "", -1)
		dn = strings.ToLower(dn)
		metricParts = strings.Split(dn, ",")
		for i, j := 0, len(metricParts)-1; i < j; i, j = i+1, j-1 {
			metricParts[i], metricParts[j] = metricParts[j], metricParts[i]
		}
		return strings.Join(metricParts[1:], "_")
	} else {
		metricName := strings.Trim(dn, " ")
		metricName = strings.Replace(metricName, " ", "_", -1)
		metricName = strings.ToLower(metricName)
		metricName = strings.TrimPrefix(metricName, "cn=")
		metricName = strings.Replace(metricName, strings.ToLower("cn=Monitor"), "", -1)
		metricName = strings.Replace(metricName, "cn=", "_", -1)
		return strings.Replace(metricName, ",", "", -1)
	}
}

func init() {
	inputs.Add("openldap", func() telegraf.Input {
		return &Openldap{}
	})
}
