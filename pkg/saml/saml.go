package saml

import (
	"bufio"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/spnego"
)

const (
	DefaultSAMLURL = "https://auth.redhat.com/auth/realms/EmployeeIDP/protocol/saml/clients/itaws"
)

// GetSAMLToken fetches a SAML assertion token using Kerberos authentication.
func GetSAMLToken(samlURL string) (string, error) {
	krb5Client, err := newKerberosClientFromCCache()
	if err != nil {
		return "", fmt.Errorf("kerberos authentication failed. Do you have a valid Kerberos ticket? %w", err)
	}

	// Extract the hostname from the SAML URL to use as the explicit SPN.
	// Without this, the SPNEGO client follows CNAMEs (e.g. to an Akamai
	// edge host) and requests a ticket for a principal the KDC doesn't know.
	samlHost := "auth.redhat.com"
	if u, err := url.Parse(samlURL); err == nil {
		samlHost = u.Hostname()
	}

	httpClient := spnego.NewClient(krb5Client, &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Resolver: &net.Resolver{PreferGo: false},
			}).DialContext,
		},
	}, "HTTP/"+samlHost)

	resp, err := httpClient.Get(samlURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch SAML token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return "", fmt.Errorf("kerberos authentication failed. Do you have a valid Kerberos ticket?")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	return extractSAMLAssertion(string(body))
}

func extractSAMLAssertion(htmlBody string) (string, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlBody))
	if err != nil {
		return "", fmt.Errorf("failed to parse HTML response: %w", err)
	}

	// Look specifically for the SAMLResponse input — the form may contain
	// multiple hidden inputs (e.g. RelayState) and we need the right one.
	samlToken, exists := doc.Find("form input[name='SAMLResponse']").Attr("value")
	if !exists || samlToken == "" {
		// Fall back to first hidden input if SAMLResponse not found by name
		samlToken, exists = doc.Find("form input[type='hidden']").Attr("value")
		if !exists || samlToken == "" {
			return "", fmt.Errorf("SAML assertion not found in response")
		}
	}

	return samlToken, nil
}

// SAMLRole represents a role/provider pair extracted from a SAML assertion.
type SAMLRole struct {
	RoleARN     string
	PrincipalARN string
}

// ParseRoles extracts the available role/provider pairs from a base64-encoded
// SAML assertion. The roles are found in Attribute elements with the Name
// "https://aws.amazon.com/SAML/Attributes/Role", where each value is a
// comma-separated pair of "principalArn,roleArn" (or "roleArn,principalArn").
func ParseRoles(samlToken string) ([]SAMLRole, error) {
	decoded, err := base64.StdEncoding.DecodeString(samlToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SAML assertion: %w", err)
	}

	var response samlResponse
	if err := xml.Unmarshal(decoded, &response); err != nil {
		return nil, fmt.Errorf("failed to parse SAML XML: %w", err)
	}

	var roles []SAMLRole
	for _, attr := range response.Assertion.AttributeStatement.Attributes {
		if attr.Name != "https://aws.amazon.com/SAML/Attributes/Role" {
			continue
		}
		for _, v := range attr.Values {
			parts := strings.SplitN(v.Value, ",", 2)
			if len(parts) != 2 {
				continue
			}
			var r SAMLRole
			// The order can be either role,principal or principal,role
			if strings.Contains(parts[0], ":role/") {
				r.RoleARN = strings.TrimSpace(parts[0])
				r.PrincipalARN = strings.TrimSpace(parts[1])
			} else {
				r.PrincipalARN = strings.TrimSpace(parts[0])
				r.RoleARN = strings.TrimSpace(parts[1])
			}
			roles = append(roles, r)
		}
	}

	return roles, nil
}

// samlResponse is a minimal representation of the SAML XML structure,
// sufficient to extract role attributes.
type samlResponse struct {
	XMLName   xml.Name      `xml:"Response"`
	Assertion samlAssertion `xml:"Assertion"`
}

type samlAssertion struct {
	AttributeStatement samlAttributeStatement `xml:"AttributeStatement"`
}

type samlAttributeStatement struct {
	Attributes []samlAttribute `xml:"Attribute"`
}

type samlAttribute struct {
	Name   string              `xml:"Name,attr"`
	Values []samlAttributeValue `xml:"AttributeValue"`
}

type samlAttributeValue struct {
	Value string `xml:",chardata"`
}

func ccachePath() string {
	if p := os.Getenv("KRB5CCNAME"); p != "" {
		return p
	}
	return fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid())
}

// resolveKDCsForRealm uses macOS scutil --dns to find the correct DNS
// nameserver for the realm's domain, then queries that nameserver directly
// via dig to discover KDC addresses. This is necessary because Go's DNS
// resolver reads /etc/resolv.conf which on macOS may point to a link-local
// address that doesn't know about VPN-scoped DNS.
func resolveKDCsForRealm(realm string) ([]string, error) {
	domain := strings.ToLower(realm)

	nameserver, err := findNameserverForDomain(domain)
	if err != nil {
		return nil, fmt.Errorf("could not find DNS server for domain %s: %w", domain, err)
	}

	kdcs, err := lookupSRVWithServer(nameserver, "_kerberos._tcp."+domain)
	if err != nil {
		return nil, err
	}

	return kdcs, nil
}

// findNameserverForDomain parses `scutil --dns` output to find the
// nameserver associated with a given domain's supplemental resolver.
func findNameserverForDomain(domain string) (string, error) {
	out, err := exec.Command("scutil", "--dns").Output()
	if err != nil {
		return "", fmt.Errorf("failed to run scutil --dns: %w", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	var inMatchingResolver bool
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "resolver #") {
			inMatchingResolver = false
		}

		if strings.HasPrefix(line, "domain") && strings.HasSuffix(line, domain) {
			inMatchingResolver = true
		}

		if inMatchingResolver && strings.HasPrefix(line, "nameserver[0]") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}

	return "", fmt.Errorf("no supplemental resolver found for domain %s", domain)
}

// lookupSRVWithServer uses dig to query a specific DNS server for SRV records.
func lookupSRVWithServer(server, name string) ([]string, error) {
	out, err := exec.Command("dig", "+short", "@"+server, name, "SRV").Output()
	if err != nil {
		return nil, fmt.Errorf("dig lookup failed: %w", err)
	}

	var kdcs []string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		// dig SRV output: priority weight port target
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 {
			host := strings.TrimSuffix(fields[3], ".")
			port := fields[2]
			kdcs = append(kdcs, host+":"+port)
		}
	}

	if len(kdcs) == 0 {
		return nil, fmt.Errorf("no KDC SRV records found for %s", name)
	}

	return kdcs, nil
}

// ensureValidTicket checks for a valid Kerberos ticket and runs kinit if
// one is not found.
func ensureValidTicket() error {
	if err := exec.Command("klist", "-s").Run(); err == nil {
		return nil
	}

	fmt.Fprintln(os.Stderr, "No valid Kerberos ticket found. Running kinit...")
	kinit := exec.Command("kinit")
	kinit.Stdin = os.Stdin
	kinit.Stdout = os.Stdout
	kinit.Stderr = os.Stderr
	if err := kinit.Run(); err != nil {
		return fmt.Errorf("kinit failed: %w", err)
	}
	return nil
}

func newKerberosClientFromCCache() (*client.Client, error) {
	if err := ensureValidTicket(); err != nil {
		return nil, err
	}

	ccache, err := credentials.LoadCCache(ccachePath())
	if err != nil {
		return nil, fmt.Errorf("failed to load Kerberos credential cache: %w", err)
	}

	krb5Conf, err := config.Load("/etc/krb5.conf")
	if err != nil {
		return nil, fmt.Errorf("failed to load Kerberos config: %w", err)
	}

	// If dns_lookup_kdc is enabled, resolve the KDC addresses ourselves
	// using the correct (VPN-aware) DNS server and inject them into the
	// config. Go's DNS resolver does not respect macOS scoped DNS on VPN.
	if krb5Conf.LibDefaults.DNSLookupKDC {
		realm := krb5Conf.LibDefaults.DefaultRealm
		kdcs, err := resolveKDCsForRealm(realm)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve KDC for realm %s: %w", realm, err)
		}

		found := false
		for i, r := range krb5Conf.Realms {
			if r.Realm == realm {
				krb5Conf.Realms[i].KDC = kdcs
				found = true
				break
			}
		}
		if !found {
			krb5Conf.Realms = append(krb5Conf.Realms, config.Realm{
				Realm: realm,
				KDC:   kdcs,
			})
		}
		krb5Conf.LibDefaults.DNSLookupKDC = false
	}

	cl, err := client.NewFromCCache(ccache, krb5Conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kerberos client: %w", err)
	}

	return cl, nil
}
