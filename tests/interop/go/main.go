package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/opentdf/platform/sdk"
)

func run(args []string) error {
	if !validArgs(args) {
		return fmt.Errorf(`usage:
  go-driver create|open INPUT OUTPUT
  go-driver create-p256|open-p256 INPUT OUTPUT
  go-driver create-features INPUT OUTPUT METADATA_FILE ATTRIBUTE [ATTRIBUTE ...]
  go-driver open-features INPUT OUTPUT EXPECTED_METADATA_FILE
  go-driver create-assertions INPUT OUTPUT PRIVATE_PEM
  go-driver open-assertions INPUT OUTPUT PUBLIC_PEM`)
	}

	platform, err := endpoint("OTDF_PLATFORM_URL")
	if err != nil {
		return err
	}
	kas, err := endpoint("OTDF_KAS_URL")
	if err != nil {
		return err
	}
	if platform.Scheme != kas.Scheme {
		return fmt.Errorf("platform and KAS must use the same URL scheme")
	}
	id, secret := os.Getenv("OTDF_CLIENT_ID"), os.Getenv("OTDF_CLIENT_SECRET")
	if id == "" || secret == "" {
		return fmt.Errorf("set OTDF_CLIENT_ID and OTDF_CLIENT_SECRET")
	}
	options := []sdk.Option{sdk.WithClientCredentials(id, secret, nil)}
	if platform.Scheme == "http" {
		options = append(options, sdk.WithInsecurePlaintextConn())
	}
	client, err := sdk.New(platform.String(), options...)
	if err != nil {
		return err
	}
	defer client.Close()

	input, err := os.Open(args[1])
	if err != nil {
		return err
	}
	defer input.Close()

	output, err := os.CreateTemp(filepath.Dir(args[2]), ".tdf-interop-*")
	if err != nil {
		return err
	}
	defer os.Remove(output.Name())
	defer output.Close()
	if strings.HasPrefix(args[0], "create") {
		err = create(client, input, output, kas.String(), args)
	} else {
		err = open(client, input, output, kas.String(), args)
	}
	if err != nil {
		return err
	}
	if err = output.Close(); err != nil {
		return err
	}
	return os.Link(output.Name(), args[2])
}

func validArgs(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "create", "open", "create-p256", "open-p256":
		return len(args) == 3
	case "create-features":
		return len(args) >= 5
	case "open-features", "create-assertions", "open-assertions":
		return len(args) == 4
	default:
		return false
	}
}

func create(client *sdk.SDK, input, output *os.File, kas string, args []string) error {
	var attributes []string
	var metadata []byte
	if args[0] == "create-features" {
		attributes = args[4:]
		var err error
		metadata, err = os.ReadFile(args[3])
		if err != nil {
			return err
		}
		if !utf8.Valid(metadata) {
			return fmt.Errorf("metadata must be UTF-8")
		}
	} else {
		attribute := os.Getenv("OTDF_ATTRIBUTE")
		if attribute == "" {
			return fmt.Errorf("set OTDF_ATTRIBUTE")
		}
		attributes = []string{attribute}
	}

	info := sdk.KASInfo{URL: kas, KID: os.Getenv("OTDF_KAS_KEY_ID"), Algorithm: "rsa:2048"}
	if args[0] == "create-p256" {
		info.Algorithm = "ec:secp256r1"
		info.KID = os.Getenv("OTDF_TEST_KAS_EC_KEY_ID")
		if info.KID == "" {
			return fmt.Errorf("set OTDF_TEST_KAS_EC_KEY_ID")
		}
	}
	options := []sdk.TDFOption{
		sdk.WithAutoconfigure(false),
		sdk.WithKasInformation(info),
		sdk.WithDataAttributes(attributes...),
		sdk.WithMetaData(string(metadata)),
		sdk.WithTargetMode("4.3.0"),
	}
	if args[0] == "create-assertions" {
		der, err := readPEM(args[3], "PRIVATE KEY")
		if err != nil {
			return err
		}
		key, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return err
		}
		privateKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("expected an RSA private key")
		}
		binding := assertion("tdf-binding", sdk.HandlingAssertion, "tdf assertion")
		publisher := assertion("publisher", sdk.BaseAssertion, "publisher assertion")
		publisher.SigningKey = sdk.AssertionKey{Alg: sdk.AssertionKeyAlgRS256, Key: privateKey}
		options = append(options, sdk.WithAssertions(binding, publisher))
	}
	_, err := client.CreateTDF(output, input, options...)
	return err
}

func open(client *sdk.SDK, input, output *os.File, kas string, args []string) error {
	options := []sdk.TDFReaderOption{sdk.WithKasAllowlist([]string{kas})}
	if args[0] == "open-p256" {
		options = append(options, sdk.WithSessionKeyType("ec:secp256r1"))
	}
	if args[0] == "open-assertions" {
		der, err := readPEM(args[3], "PUBLIC KEY")
		if err != nil {
			return err
		}
		key, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return err
		}
		publicKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected an RSA public key")
		}
		options = append(options, sdk.WithAssertionVerificationKeys(sdk.AssertionVerificationKeys{
			Keys: map[string]sdk.AssertionKey{
				"publisher": {Alg: sdk.AssertionKeyAlgRS256, Key: publicKey},
			},
		}))
	}
	tdf, err := client.LoadTDF(input, options...)
	if err != nil {
		return err
	}
	if args[0] == "open-features" {
		expected, err := os.ReadFile(args[3])
		if err != nil {
			return err
		}
		metadata, err := tdf.UnencryptedMetadata()
		if err != nil {
			return err
		}
		if !bytes.Equal(metadata, expected) {
			return fmt.Errorf("decrypted metadata differs")
		}
	}
	if args[0] == "open-assertions" {
		assertions := tdf.Manifest().Assertions
		if len(assertions) != 2 {
			return fmt.Errorf("expected exactly two assertions")
		}
		ids := map[string]bool{assertions[0].ID: true, assertions[1].ID: true}
		if !ids["tdf-binding"] || !ids["publisher"] {
			return fmt.Errorf("missing required assertions")
		}
	}
	_, err = tdf.WriteTo(output)
	return err
}

func assertion(id string, kind sdk.AssertionType, value string) sdk.AssertionConfig {
	return sdk.AssertionConfig{
		ID: id, Type: kind, Scope: sdk.PayloadScope, AppliesToState: sdk.Unencrypted,
		Statement: sdk.Statement{Format: "text/plain", Schema: "urn:opentdf:test:assertion", Value: value},
	}
}

func readPEM(path, kind string) ([]byte, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != kind || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("expected a PEM %s", kind)
	}
	return block.Bytes, nil
}

func endpoint(name string) (*url.URL, error) {
	value, err := url.Parse(os.Getenv(name))
	if err == nil && value.Hostname() != "" && value.User == nil &&
		(value.Path == "/" || value.Path == "") && value.RawQuery == "" && value.Fragment == "" {
		host := value.Hostname()
		if value.Scheme == "https" || value.Scheme == "http" &&
			(host == "localhost" || host == "127.0.0.1" || host == "::1") {
			value.Path = ""
			return value, nil
		}
	}
	return nil, fmt.Errorf("%s must be an HTTPS origin or a loopback HTTP origin", name)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
