import com.connectrpc.Code;
import com.connectrpc.ConnectException;
import io.opentdf.platform.sdk.Config;
import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.SDK;
import io.opentdf.platform.sdk.SDKBuilder;
import io.opentdf.platform.sdk.SDKException;

import java.net.URI;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Set;

public final class TdfDriver {
    public static void main(String[] args) throws Exception {
        String operation = args.length == 0 ? "" : args[0];
        boolean validArgs = switch (operation) {
            case "create", "open", "expect-denied" -> args.length == 3;
            case "create-features" -> args.length >= 5;
            case "open-features" -> args.length == 4;
            default -> false;
        };
        if (!validArgs) {
            throw new IllegalArgumentException("""
                    Usage:
                      create|open|expect-denied INPUT OUTPUT
                      create-features INPUT OUTPUT METADATA_FILE ATTRIBUTE [ATTRIBUTE ...]
                      open-features INPUT OUTPUT EXPECTED_METADATA_FILE
                    """);
        }

        URI platform = endpoint("OTDF_PLATFORM_URL");
        URI kas = endpoint("OTDF_KAS_URL");
        var builder = SDKBuilder.newBuilder()
                .platformEndpoint(platform.toString())
                .clientSecret(required("OTDF_CLIENT_ID"), required("OTDF_CLIENT_SECRET"))
                .useInsecurePlaintextConnection(isHttp(platform) || isHttp(kas));
        String trustDir = System.getenv("OTDF_TRUST_CERT_DIR");
        if (trustDir != null && !trustDir.isBlank()) {
            builder.sslFactoryFromDirectory(trustDir);
        }

        Path input = Path.of(args[1]);
        Path output = Path.of(args[2]).toAbsolutePath();
        if (Files.exists(output)) {
            throw new IllegalArgumentException("Output already exists: " + output);
        }

        try (SDK sdk = builder.build()) {
            var readConfig = Config.newTDFReaderConfig(
                    Config.WithKasAllowlist(kas.toString()),
                    Config.WithSessionKeyType(KeyType.RSA2048Key));
            if (operation.equals("expect-denied")) {
                expectDenied(sdk, input, readConfig, kas);
                return;
            }

            Path temp = Files.createTempFile(output.getParent(), ".tdf-interop-", ".tmp");
            try {
                try (var stream = Files.newOutputStream(temp)) {
                    if (operation.equals("create") || operation.equals("create-features")) {
                        boolean withFeatures = operation.equals("create-features");
                        String[] attributes = withFeatures
                                ? Arrays.copyOfRange(args, 4, args.length)
                                : new String[]{required("OTDF_ATTRIBUTE")};
                        String metadata = withFeatures ? Files.readString(Path.of(args[3])) : "";
                        var kasInfo = new Config.KASInfo();
                        kasInfo.URL = kas.toString();
                        kasInfo.KID = System.getenv("OTDF_KAS_KEY_ID");
                        var config = Config.newTDFConfig(
                                Config.withTargetMode("4.3.0"),
                                Config.withAutoconfigure(false),
                                Config.WithWrappingKeyAlg(KeyType.RSA2048Key),
                                Config.withKasInformation(kasInfo),
                                Config.withDataAttributes(attributes),
                                Config.withMetaData(metadata));
                        try (var plaintext = Files.newInputStream(input)) {
                            sdk.createTDF(plaintext, stream, config);
                        }
                    } else {
                        try (var channel = FileChannel.open(input)) {
                            var reader = sdk.loadTDF(channel, readConfig);
                            if (operation.equals("open-features")
                                    && !Files.readString(Path.of(args[3])).equals(reader.getMetadata())) {
                                throw new IllegalStateException("Decrypted metadata differs");
                            }
                            reader.readPayload(stream);
                        }
                    }
                }
                Files.move(temp, output);
            } finally {
                Files.deleteIfExists(temp);
            }
        }
    }

    private static void expectDenied(SDK sdk, Path input, Config.TDFReaderConfig config, URI kas) throws Exception {
        try (var channel = FileChannel.open(input)) {
            try {
                sdk.loadTDF(channel, config);
            } catch (SDK.SplitKeyException openError) {
                // The reader drops the underlying KAS status when it reports a split-key error.
                channel.position(0);
                var manifest = SDK.readManifest(channel);
                var encryption = manifest.encryptionInformation;
                if (encryption.keyAccessObj.size() != 1
                        || !kas.equals(URI.create(encryption.keyAccessObj.get(0).url))) {
                    throw openError;
                }
                try {
                    sdk.getServices().kas().unwrap(encryption.keyAccessObj.get(0),
                            encryption.policy, KeyType.RSA2048Key);
                } catch (SDKException rewrapError) {
                    if (rewrapError.getCause() instanceof ConnectException cause
                            && cause.getCode() == Code.PERMISSION_DENIED) {
                        System.out.println("KAS denied access (permission_denied)");
                        return;
                    }
                    throw rewrapError;
                }
                throw openError;
            }
        }
        throw new IllegalStateException("KAS unexpectedly granted access");
    }

    private static URI endpoint(String key) {
        var uri = URI.create(required(key));
        if (uri.getHost() == null || uri.getUserInfo() != null
                || (!"https".equals(uri.getScheme()) && !isHttp(uri))) {
            throw new IllegalArgumentException(key + " must be a valid HTTP(S) URL without credentials");
        }
        if (isHttp(uri) && !Set.of("localhost", "127.0.0.1", "[::1]").contains(uri.getHost())) {
            throw new IllegalArgumentException(key + " must use HTTPS outside loopback");
        }
        return uri;
    }

    private static boolean isHttp(URI uri) {
        return "http".equals(uri.getScheme());
    }

    private static String required(String key) {
        String value = System.getenv(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Set " + key);
        }
        return value;
    }
}
