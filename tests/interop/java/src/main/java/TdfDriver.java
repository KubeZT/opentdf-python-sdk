import com.connectrpc.Code;
import com.connectrpc.ConnectException;
import io.opentdf.platform.sdk.AssertionConfig;
import io.opentdf.platform.sdk.Config;
import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.SDK;
import io.opentdf.platform.sdk.SDKBuilder;
import io.opentdf.platform.sdk.SDKException;

import java.net.URI;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

public final class TdfDriver {
    public static void main(String[] args) throws Exception {
        String operation = args.length == 0 ? "" : args[0];
        boolean validArgs = switch (operation) {
            case "create", "open", "create-p256", "open-p256", "expect-denied" -> args.length == 3;
            case "create-features" -> args.length >= 5;
            case "open-features", "create-assertions", "open-assertions" -> args.length == 4;
            default -> false;
        };
        if (!validArgs) {
            throw new IllegalArgumentException("""
                    Usage:
                      create|open|expect-denied INPUT OUTPUT
                      create-p256|open-p256 INPUT OUTPUT
                      create-features INPUT OUTPUT METADATA_FILE ATTRIBUTE [ATTRIBUTE ...]
                      open-features INPUT OUTPUT EXPECTED_METADATA_FILE
                      create-assertions INPUT OUTPUT PRIVATE_PEM
                      open-assertions INPUT OUTPUT PUBLIC_PEM
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
            KeyType sessionKey = operation.equals("open-p256") ? KeyType.EC256Key : KeyType.RSA2048Key;
            var readConfig = Config.newTDFReaderConfig(
                    Config.WithKasAllowlist(kas.toString()),
                    Config.WithSessionKeyType(sessionKey));
            if (operation.equals("open-assertions")) {
                var key = KeyFactory.getInstance("RSA").generatePublic(
                        new X509EncodedKeySpec(readPem(Path.of(args[3]), "PUBLIC KEY")));
                var keys = new Config.AssertionVerificationKeys();
                keys.keys = Map.of("publisher", new AssertionConfig.AssertionKey(
                        AssertionConfig.AssertionKeyAlg.RS256, key));
                Config.withAssertionVerificationKeys(keys).accept(readConfig);
            }
            if (operation.equals("expect-denied")) {
                expectDenied(sdk, input, readConfig, kas);
                return;
            }

            Path temp = Files.createTempFile(output.getParent(), ".tdf-interop-", ".tmp");
            try {
                try (var stream = Files.newOutputStream(temp)) {
                    if (operation.startsWith("create")) {
                        boolean withFeatures = operation.equals("create-features");
                        String[] attributes = withFeatures
                                ? Arrays.copyOfRange(args, 4, args.length)
                                : new String[]{required("OTDF_ATTRIBUTE")};
                        String metadata = withFeatures ? Files.readString(Path.of(args[3])) : "";
                        var kasInfo = new Config.KASInfo();
                        kasInfo.URL = kas.toString();
                        KeyType wrappingKey = KeyType.RSA2048Key;
                        if (operation.equals("create-p256")) {
                            wrappingKey = KeyType.EC256Key;
                            kasInfo.Algorithm = wrappingKey.toString();
                            kasInfo.KID = required("OTDF_TEST_KAS_EC_KEY_ID");
                        } else {
                            kasInfo.KID = System.getenv("OTDF_KAS_KEY_ID");
                        }
                        var config = Config.newTDFConfig(
                                Config.withTargetMode("4.3.0"),
                                Config.withAutoconfigure(false),
                                Config.WithWrappingKeyAlg(wrappingKey),
                                Config.withKasInformation(kasInfo),
                                Config.withDataAttributes(attributes),
                                Config.withMetaData(metadata));
                        if (operation.equals("create-assertions")) {
                            var key = KeyFactory.getInstance("RSA").generatePrivate(
                                    new PKCS8EncodedKeySpec(readPem(Path.of(args[3]), "PRIVATE KEY")));
                            var binding = assertion("tdf-binding", AssertionConfig.Type.HandlingAssertion,
                                    "tdf assertion");
                            var publisher = assertion("publisher", AssertionConfig.Type.BaseAssertion,
                                    "publisher assertion");
                            publisher.signingKey = new AssertionConfig.AssertionKey(
                                    AssertionConfig.AssertionKeyAlg.RS256, key);
                            Config.withAssertionConfig(binding, publisher).accept(config);
                        }
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
                            if (operation.equals("open-assertions")) {
                                var assertions = reader.getManifest().assertions;
                                if (assertions == null || assertions.size() != 2
                                        || !Set.of(assertions.get(0).id, assertions.get(1).id)
                                        .equals(Set.of("tdf-binding", "publisher"))) {
                                    throw new IllegalStateException("Missing required assertions");
                                }
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

    private static AssertionConfig assertion(String id, AssertionConfig.Type kind, String value) {
        var assertion = new AssertionConfig();
        assertion.id = id;
        assertion.type = kind;
        assertion.scope = AssertionConfig.Scope.Payload;
        assertion.appliesToState = AssertionConfig.AppliesToState.Unencrypted;
        assertion.statement = new AssertionConfig.Statement();
        assertion.statement.format = "text/plain";
        assertion.statement.schema = "urn:opentdf:test:assertion";
        assertion.statement.value = value;
        return assertion;
    }

    private static byte[] readPem(Path path, String kind) throws Exception {
        String pem = Files.readString(path).strip();
        String begin = "-----BEGIN " + kind + "-----";
        String end = "-----END " + kind + "-----";
        if (!pem.startsWith(begin) || !pem.endsWith(end)) {
            throw new IllegalArgumentException("Expected a PEM " + kind);
        }
        String base64 = pem.substring(begin.length(), pem.length() - end.length());
        return Base64.getDecoder().decode(base64.replaceAll("\\s", ""));
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
