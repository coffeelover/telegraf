package openldap

import (
	"testing"

	"github.com/influxdata/telegraf/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/ldap.v3"
)

func TestOpenldapMockResult(t *testing.T) {
	var acc testutil.Accumulator

	mockSearchResult := ldap.SearchResult{
		Entries: []*ldap.Entry{
			{
				DN:         "cn=Total,cn=Connections,cn=Monitor",
				Attributes: []*ldap.EntryAttribute{{Name: "monitorCounter", Values: []string{"1"}}},
			},
		},
		Referrals: []string{},
		Controls:  []ldap.Control{},
	}

	o := &Openldap{
		URI: "ldap://localhost",
	}

	gatherSearchResult(&mockSearchResult, o, &acc)
	commonTests(t, o, &acc)
}

func TestOpenldapNoConnectionIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	o := &Openldap{
		Host: "nosuchhost",
		Port: 389,
	}

	var acc testutil.Accumulator
	err := o.Gather(&acc)
	require.NoError(t, err)        // test that we didn't return an error
	assert.Zero(t, acc.NFields())  // test that we didn't return any fields
	assert.NotEmpty(t, acc.Errors) // test that we set an error
}

func TestOpenldapGeneratesMetricsIntegration(t *testing.T) {
	t.Skip("skipping test as unable to read LDAP response packet: unexpected EOF")

	o := &Openldap{
		Host: testutil.GetLocalHost(),
		Port: 389,
	}

	var acc testutil.Accumulator
	err := o.Gather(&acc)
	require.NoError(t, err)
	commonTests(t, o, &acc)
}

func TestOpenldapStartTLSIntegration(t *testing.T) {
	t.Skip("skipping test as unable to read LDAP response packet: unexpected EOF")

	o := &Openldap{
		Host: testutil.GetLocalHost(),
		Port: 389,
		SSL:  "starttls",
	}
	o.InsecureSkipVerify = true

	var acc testutil.Accumulator
	err := o.Gather(&acc)
	require.NoError(t, err)
	commonTests(t, o, &acc)
}

func TestOpenldapLDAPSIntegration(t *testing.T) {
	t.Skip("skipping test as unable to read LDAP response packet: unexpected EOF")

	o := &Openldap{
		Host: testutil.GetLocalHost(),
		Port: 636,
		SSL:  "ldaps",
	}
	o.InsecureSkipVerify = true

	var acc testutil.Accumulator
	err := o.Gather(&acc)
	require.NoError(t, err)
	commonTests(t, o, &acc)
}

func TestOpenldapInvalidSSLIntegration(t *testing.T) {
	t.Skip("skipping test as unable to read LDAP response packet: unexpected EOF")

	o := &Openldap{
		Host: testutil.GetLocalHost(),
		Port: 636,
		SSL:  "invalid",
	}
	o.InsecureSkipVerify = true

	var acc testutil.Accumulator
	err := o.Gather(&acc)
	require.NoError(t, err)        // test that we didn't return an error
	assert.Zero(t, acc.NFields())  // test that we didn't return any fields
	assert.NotEmpty(t, acc.Errors) // test that we set an error
}

func TestOpenldapBindIntegration(t *testing.T) {
	t.Skip("skipping test as unable to read LDAP response packet: unexpected EOF")

	o := &Openldap{
		Host:         testutil.GetLocalHost(),
		Port:         389,
		SSL:          "",
		BindDn:       "cn=manager,cn=config",
		BindPassword: "secret",
	}
	o.InsecureSkipVerify = true

	var acc testutil.Accumulator
	err := o.Gather(&acc)
	require.NoError(t, err)
	commonTests(t, o, &acc)
}

func commonTests(t *testing.T, o *Openldap, acc *testutil.Accumulator) {
	assert.Empty(t, acc.Errors, "accumulator had no errors")
	assert.True(t, acc.HasMeasurement("openldap"), "Has a measurement called 'openldap'")
	assert.True(t, acc.HasInt64Field("openldap", "total_connections"), "Has an integer field called total_connections")
}

func TestOpenldapReverseMetricsIntegration(t *testing.T) {
	t.Skip("skipping test as unable to read LDAP response packet: unexpected EOF")

	o := &Openldap{
		Host:               testutil.GetLocalHost(),
		Port:               389,
		SSL:                "",
		BindDn:             "cn=manager,cn=config",
		BindPassword:       "secret",
		ReverseMetricNames: true,
	}
	o.InsecureSkipVerify = true

	var acc testutil.Accumulator
	err := o.Gather(&acc)
	require.NoError(t, err)
	assert.True(t, acc.HasInt64Field("openldap", "connections_total"), "Has an integer field called connections_total")
}
