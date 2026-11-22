package main

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/opentdf/platform/sdk"
)

func run(args []string) error {
	if !validArgs(args) {
		return fmt.Errorf(`usage:
  go-driver create|open INPUT OUTPUT
  go-driver create-features INPUT OUTPUT METADATA_FILE ATTRIBUTE [ATTRIBUTE ...]
  go-driver open-features INPUT OUTPUT EXPECTED_METADATA_FILE`)
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
	if args[0] == "create" || args[0] == "create-features" {
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
	case "create", "open":
		return len(args) == 3
	case "create-features":
		return len(args) >= 5
	case "open-features":
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

	_, err := client.CreateTDF(output, input,
		sdk.WithAutoconfigure(false),
		sdk.WithKasInformation(sdk.KASInfo{
			URL: kas, KID: os.Getenv("OTDF_KAS_KEY_ID"), Algorithm: "rsa:2048",
		}),
		sdk.WithDataAttributes(attributes...),
		sdk.WithMetaData(string(metadata)),
		sdk.WithTargetMode("4.3.0"),
	)
	return err
}

func open(client *sdk.SDK, input, output *os.File, kas string, args []string) error {
	tdf, err := client.LoadTDF(input, sdk.WithKasAllowlist([]string{kas}))
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
	_, err = tdf.WriteTo(output)
	return err
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
