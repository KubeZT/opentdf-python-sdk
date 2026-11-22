package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/opentdf/platform/sdk"
)

func run(args []string) error {
	if len(args) != 3 || (args[0] != "create" && args[0] != "open") {
		return fmt.Errorf("usage: go-driver create|open INPUT OUTPUT")
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
	if args[0] == "create" {
		attribute := os.Getenv("OTDF_ATTRIBUTE")
		if attribute == "" {
			return fmt.Errorf("set OTDF_ATTRIBUTE")
		}
		_, err = client.CreateTDF(output, input,
			sdk.WithAutoconfigure(false),
			sdk.WithKasInformation(sdk.KASInfo{
				URL: kas.String(), KID: os.Getenv("OTDF_KAS_KEY_ID"), Algorithm: "rsa:2048",
			}),
			sdk.WithDataAttributes(attribute),
			sdk.WithTargetMode("4.3.0"),
		)
	} else {
		var tdf *sdk.Reader
		tdf, err = client.LoadTDF(input, sdk.WithKasAllowlist([]string{kas.String()}))
		if err == nil {
			_, err = tdf.WriteTo(output)
		}
	}
	if err != nil {
		return err
	}
	if err = output.Close(); err != nil {
		return err
	}
	return os.Link(output.Name(), args[2])
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
