package dev.fieldseal.core;

import dev.fieldseal.core.errors.CommitmentInvalidError;
import dev.fieldseal.core.errors.ConfigurationError;
import dev.fieldseal.core.errors.InvalidArgumentError;
import dev.fieldseal.core.errors.KeyUnavailableError;
import dev.fieldseal.core.errors.ModeViolationError;
import dev.fieldseal.core.errors.NotCiphertextError;
import dev.fieldseal.core.errors.SuiteNotAllowedError;
import dev.fieldseal.core.errors.SuiteProvisionalError;
import dev.fieldseal.core.errors.TagInvalidError;
import dev.fieldseal.core.errors.UnknownFormatVersionError;
import dev.fieldseal.core.internal.aead.Aead;
import dev.fieldseal.core.internal.cache.DekCache;
import dev.fieldseal.core.internal.commitment.Commitment;
import dev.fieldseal.core.internal.context.CanonicalContext;
import dev.fieldseal.core.internal.context.ContextFields;
import dev.fieldseal.core.internal.context.Purpose;
import dev.fieldseal.core.internal.envelope.BufferLimits;
import dev.fieldseal.core.internal.envelope.DecryptFront;
import dev.fieldseal.core.internal.envelope.EnvelopeCodec;
import dev.fieldseal.core.internal.envelope.Operand;
import dev.fieldseal.core.internal.envelope.ParsedEnvelope;
import dev.fieldseal.core.internal.kdf.Hkdf;
import dev.fieldseal.core.internal.kdf.KeyDerivation;
import dev.fieldseal.core.internal.registry.AllowList;
import dev.fieldseal.core.internal.registry.Registry;
import dev.fieldseal.core.internal.registry.Suite;
import dev.fieldseal.core.keyprovider.EnvelopeHeader;
import dev.fieldseal.core.keyprovider.KeyMaterial;
import dev.fieldseal.core.keyprovider.KeyProvider;
import dev.fieldseal.core.keyprovider.KeyRequest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.LongSupplier;

/**
 * The Fieldseal client (docs/09 §2; docs/27 §4): one immutable, validated configuration, and the
 * spec §11.1 operations over it. Bytes in, bytes out. Every operation is synchronous, performs no
 * I/O, and is safe to call from any number of threads (docs/09 §10).
 *
 * <p><b>Order at the API boundary</b> ({@code api-boundary-order}, pinned and tested): on {@code
 * encrypt}, {@code MODE_VIOLATION}, then {@code SUITE_PROVISIONAL}, then the operand (a null one
 * is {@code INVALID_ARGUMENT}; an over-long one {@code LENGTH_EXCEEDED}), then the context, then key
 * acquisition. On {@code rotate}, the same first two, then the operand as {@code decrypt} reads it,
 * except that a non-envelope is {@code NOT_CIPHERTEXT} in every mode (spec §11.1).
 *
 * <p><b>Order on {@code decrypt}</b> ({@code decrypt-order}): recognition ({@code
 * UNKNOWN_FORMAT_VERSION}; a non-envelope is {@code NOT_CIPHERTEXT} in {@code strict} and returned
 * as-is otherwise), then {@code LENGTH_EXCEEDED}, then {@code SUITE_NOT_ALLOWED}, then the context,
 * then {@code KEY_UNAVAILABLE}, then per candidate key: the commitment, and only once it verifies,
 * the tag ({@code TAG_INVALID}). No candidate verifying is {@code COMMITMENT_INVALID}; this core
 * never raises {@code AAD_MISMATCH}, because under spec §6.3's dual binding a wrong context and a
 * wrong key cannot be told apart (docs/09 §3.2 step 7, G5).
 */
public final class Fieldseal {

    /** The in-code arming form spec §4.8 asks each binding to name. */
    static final String IN_CODE_ARMING = "Fieldseal.builder().armProvisionalSuites(true)";

    /** docs/08 §6's test-configuration gate; the static provider warns outside it. */
    static final String TEST_MODE_VARIABLE = "FIELDSEAL_TEST_MODE";

    private static final Commitment.Kdf KDF = Hkdf::derive;
    private static final HexFormat HEX = HexFormat.of();

    /** How a record key is derived: {@link KeyDerivation#recordKey}, or a test's recorder. */
    @FunctionalInterface
    interface RecordKeys {
        byte[] derive(Suite suite, byte[] dek, byte[] keyId, byte[] msgSeed, byte[] cc);
    }

    private final KeyProvider provider;
    private final ReadMode readMode;
    private final Suite writeSuite;
    private final AllowList allowed;
    private final boolean armed;
    private final RecordKeys recordKeys;
    private final SecureRandom random = new SecureRandom();

    private Fieldseal(Builder b, KeyProvider provider, Suite writeSuite, AllowList allowed,
            boolean armed) {
        this.provider = provider;
        this.readMode = b.readMode;
        this.writeSuite = writeSuite;
        this.allowed = allowed;
        this.armed = armed;
        this.recordKeys = b.recordKeys;
    }

    public static Builder builder() {
        return new Builder();
    }

    // ----------------------------------------------------------------------------------------
    // The operations. Each public one builds the operand once (docs/27 §6.2) and enters the
    // package-private pipeline the seam tests drive.

    /** Encrypts {@code plaintext} under the write suite, bound to {@code ctx} (spec §11.1). */
    public byte[] encrypt(byte[] plaintext, FieldContext ctx) {
        return encrypt(plaintext == null ? null : Operand.of(plaintext), ctx);
    }

    /**
     * Decrypts {@code envelope} under {@code ctx}. In {@code permissive} and {@code readonly}, an
     * input that is not an envelope is returned as-is: the same array (spec §10.3).
     */
    public byte[] decrypt(byte[] envelope, FieldContext ctx) {
        return decrypt(envelope == null ? null : Operand.of(envelope), ctx);
    }

    /**
     * Re-encrypts {@code envelope} under the current write suite and key, with a fresh seed and
     * nonce: ciphertext to ciphertext in every mode (spec §11.1).
     */
    public byte[] rotate(byte[] envelope, FieldContext ctx) {
        return rotate(envelope == null ? null : Operand.of(envelope), ctx);
    }

    /**
     * Whether {@code bytes} is an envelope under a registered suite (spec §3.4). Independent of
     * this client's allow-list; never decrypts.
     */
    public boolean isCiphertext(byte[] bytes) {
        return EnvelopeCodec.isCiphertext(bytes);
    }

    /**
     * Fetches key material for {@code contexts} ahead of the value path (docs/09 §3.6): the only
     * place a key provider may do I/O. Call it on a schedule shorter than the cache's max age: it
     * refreshes keys that are still cached, restarting their age and use budget.
     *
     * <p>Every failure, including a null collection or a null context, completes the returned
     * future exceptionally; none is thrown. What a failure leaves cached is the provider's
     * contract (for the envelope provider: {@link KeyProviders#envelope}). An empty collection
     * completes at once.
     */
    public CompletableFuture<Void> warm(Collection<FieldContext> contexts) {
        try {
            if (contexts == null) {
                throw new InvalidArgumentError("the contexts to warm are null");
            }
            List<KeyRequest> requests = new ArrayList<>();
            for (FieldContext c : contexts) {
                requests.add(request(requireContext(c), Purpose.ENCRYPT));
            }
            CompletableFuture<Void> f = provider.warm(requests);
            return f != null ? f : CompletableFuture.failedFuture(
                    new KeyUnavailableError("the key provider's warm returned no future"));
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    byte[] encrypt(Operand plaintext, FieldContext ctx) {
        refuseInReadonly("encrypt");
        requireArmed();
        if (plaintext == null) {
            throw new InvalidArgumentError("the plaintext is null");
        }
        BufferLimits.requirePlaintextWithinBound(plaintext);
        FieldContext c = requireContext(ctx);
        return seal(bytes(plaintext), c);
    }

    byte[] decrypt(Operand envelope, FieldContext ctx) {
        if (envelope == null) {
            throw new InvalidArgumentError("the envelope is null");
        }
        return switch (EnvelopeCodec.frontOfDecrypt(envelope)) {
            case DecryptFront.ReservedVersion r -> throw reservedVersion();
            case DecryptFront.NonEnvelope n -> {
                if (readMode == ReadMode.STRICT) {
                    throw new NotCiphertextError("not a recognizable envelope, in strict mode"
                            + " (spec §3.4, §10.3)");
                }
                yield bytes(envelope);
            }
            case DecryptFront.Ready r -> open(r.envelope(), envelope, ctx);
        };
    }

    byte[] rotate(Operand envelope, FieldContext ctx) {
        refuseInReadonly("rotate");
        requireArmed();
        if (envelope == null) {
            throw new InvalidArgumentError("the envelope is null");
        }
        byte[] plaintext = switch (EnvelopeCodec.frontOfDecrypt(envelope)) {
            case DecryptFront.ReservedVersion r -> throw reservedVersion();
            case DecryptFront.NonEnvelope n -> throw new NotCiphertextError("rotate takes an"
                    + " envelope in every read mode (spec §11.1)");
            case DecryptFront.Ready r -> open(r.envelope(), envelope, ctx);
        };
        try {
            BufferLimits.requirePlaintextWithinBound(Operand.of(plaintext));
            return seal(plaintext, ctx);
        } finally {
            // An intermediate plaintext the core produced and the caller never sees (docs/09 §3).
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    // ----------------------------------------------------------------------------------------
    // docs/09 §3.1 steps 3-13 and §3.2 steps 3-7.

    private byte[] seal(byte[] plaintext, FieldContext ctx) {
        Suite suite = writeSuite;
        Aead aead = Aead.forSuite(suite).orElseThrow(
                () -> new IllegalStateException("write suite " + suite.hexId() + " is not built"));
        KeyMaterial km = encryptionKey(request(ctx, Purpose.ENCRYPT));
        byte[] msgSeed = new byte[32];
        byte[] nonce = new byte[suite.nonceLen()];
        random.nextBytes(msgSeed);
        random.nextBytes(nonce);
        byte[] cc = CanonicalContext.encode(fields(ctx, suite.id()));
        byte[] recordKey = recordKeys.derive(suite, km.key(), km.keyId(), msgSeed, cc);
        try {
            byte[] env = EnvelopeCodec.newEnvelope(suite, km.keyId(), msgSeed, nonce,
                    plaintext.length);
            aead.sealInto(recordKey, nonce,
                    CanonicalContext.aad(EnvelopeCodec.FMT_VER, km.keyId(), msgSeed, cc),
                    plaintext, env, EnvelopeCodec.ciphertextOffset(suite));
            byte[] commitment = Commitment.compute(suite, recordKey, KDF);
            System.arraycopy(commitment, 0, env,
                    (int) EnvelopeCodec.commitmentOffset(suite, plaintext.length),
                    commitment.length);
            return env;
        } finally {
            Arrays.fill(recordKey, (byte) 0);
        }
    }

    private byte[] open(ParsedEnvelope p, Operand operand, FieldContext ctx) {
        Suite suite = p.suite();
        if (!allowed.permits(suite.id())) {
            throw new SuiteNotAllowedError("suite " + suite.hexId() + " is not on this client's"
                    + " allow-list (spec §4.3); key_id " + HEX.formatHex(p.keyId()));
        }
        FieldContext c = requireContext(ctx);
        // docs/09 §3.2 step 4: the context's suite_id is the envelope's, never the write suite.
        byte[] cc = CanonicalContext.encode(fields(c, suite.id()));
        List<byte[]> candidates = decryptionKeys(
                new EnvelopeHeader(suite.id(), p.keyId(), request(c, Purpose.ENCRYPT)), p, c);
        Aead aead = Aead.forSuite(suite).orElseThrow(
                () -> new IllegalStateException("allow-listed suite " + suite.hexId()
                        + " is not built"));
        byte[] aad = CanonicalContext.aad(EnvelopeCodec.FMT_VER, p.keyId(), p.msgSeed(), cc);
        byte[] env = bytes(operand);
        for (byte[] dek : candidates) {
            byte[] recordKey = recordKeys.derive(suite, dek, p.keyId(), p.msgSeed(), cc);
            try {
                if (!Commitment.verify(suite, recordKey, p.commitment(), KDF)) {
                    continue;
                }
                Aead.Opened opened = aead.open(recordKey, p.nonce(), aad, env,
                        (int) p.ctOffset(), (int) p.ctAndTagLen());
                if (opened instanceof Aead.Opened.Plaintext pt) {
                    return pt.bytes();
                }
                throw new TagInvalidError("the tag did not verify under a key whose commitment"
                        + " did (spec §9): " + describe(p, c));
            } finally {
                Arrays.fill(recordKey, (byte) 0);
            }
        }
        throw new CommitmentInvalidError("no candidate key's commitment verified (spec §4.6):"
                + " the key or the context is not the one this envelope was written under; "
                + describe(p, c));
    }

    // ----------------------------------------------------------------------------------------
    // The key provider boundary: every failure is KEY_UNAVAILABLE (docs/27 §4), and what the
    // provider returns is read, never written or kept (docs/09 §8.1).

    private KeyMaterial encryptionKey(KeyRequest r) {
        KeyMaterial km;
        try {
            km = provider.encryptionKey(r);
        } catch (KeyUnavailableError e) {
            throw e;
        } catch (RuntimeException e) {
            throw new KeyUnavailableError("the key provider failed for " + r + ": "
                    + e.getClass().getName(), e);
        }
        if (km == null || km.key() == null || km.key().length == 0) {
            throw new KeyUnavailableError("the key provider returned no key for " + r);
        }
        if (km.keyId() == null || km.keyId().length != KeyMaterial.KEY_ID_LEN) {
            throw new KeyUnavailableError("the key provider returned a key_id that is not 16"
                    + " bytes for " + r + " (spec §3.1)");
        }
        return km;
    }

    private List<byte[]> decryptionKeys(EnvelopeHeader h, ParsedEnvelope p, FieldContext c) {
        List<byte[]> keys;
        try {
            keys = provider.decryptionKeys(h);
        } catch (KeyUnavailableError e) {
            throw e;
        } catch (RuntimeException e) {
            throw new KeyUnavailableError("the key provider failed: " + e.getClass().getName()
                    + "; " + describe(p, c), e);
        }
        if (keys == null || keys.isEmpty()) {
            throw new KeyUnavailableError("the key provider has no key for this envelope; "
                    + describe(p, c));
        }
        for (byte[] k : keys) {
            if (k == null || k.length == 0) {
                throw new KeyUnavailableError("the key provider returned an empty candidate; "
                        + describe(p, c));
            }
        }
        return keys;
    }

    // ----------------------------------------------------------------------------------------

    private void refuseInReadonly(String operation) {
        if (readMode == ReadMode.READONLY) {
            throw new ModeViolationError(operation, "readonly");
        }
    }

    private void requireArmed() {
        if (writeSuite.provisional() && !armed) {
            throw new SuiteProvisionalError(writeSuite.id(), IN_CODE_ARMING);
        }
    }

    private static UnknownFormatVersionError reservedVersion() {
        return new UnknownFormatVersionError("fmt_ver 0x02 is reserved for a future format"
                + " (spec §3.1, §3.4); this data was written by a newer implementation");
    }

    private static FieldContext requireContext(FieldContext ctx) {
        if (ctx == null) {
            throw new InvalidArgumentError("the field context is null");
        }
        return ctx;
    }

    /** The purpose is always the core's own (spec §6.1): never a string a caller supplied. */
    private static KeyRequest request(FieldContext c, String purpose) {
        return new KeyRequest(c.tableUuid(), c.columnUuid(), c.tenantId(), c.rowId(), purpose);
    }

    private static ContextFields fields(FieldContext c, int suiteId) {
        return new ContextFields(suiteId, c.tableUuid(), c.columnUuid(), c.tenantId(), c.rowId(),
                Purpose.ENCRYPT);
    }

    /** The operand's array: the public entry points build only array operands. */
    private static byte[] bytes(Operand op) {
        if (op instanceof Operand.ArrayOperand a) {
            return a.bytes();
        }
        throw new IllegalStateException("only an array operand carries content past the guard");
    }

    /** spec §9 / docs/09 §9: suite, key_id and the context identifiers, all public. */
    private static String describe(ParsedEnvelope p, FieldContext c) {
        return "suite " + p.suite().hexId() + ", key_id " + HEX.formatHex(p.keyId()) + ", table "
                + HEX.formatHex(c.tableUuid()) + ", column " + HEX.formatHex(c.columnUuid());
    }

    // ----------------------------------------------------------------------------------------
    // Configuration reflection (docs/09 §2): resolved values, nothing mutable, no provider.

    public ReadMode readMode() {
        return readMode;
    }

    public int writeSuite() {
        return writeSuite.id();
    }

    /** Unmodifiable, in ascending order. */
    public Set<Integer> allowedSuites() {
        return allowed.suites();
    }

    /** Whether provisional suites are armed (spec §4.8), by either mechanism. */
    public boolean provisionalArmed() {
        return armed;
    }

    /**
     * Builds a {@link Fieldseal}. {@link #build} validates everything and the result is
     * immutable (docs/09 §2).
     */
    public static final class Builder {
        private KeyProvider keyProvider;
        private Set<Integer> allowedSuites;
        private Integer writeSuite;
        private ReadMode readMode = ReadMode.STRICT;
        private boolean armProvisionalSuites;
        private CachePolicy cachePolicy;
        private Executor warmExecutor;
        private boolean warmExecutorSet;
        private Consumer<String> onWarning;
        private Function<String, String> environment = System::getenv;
        private RecordKeys recordKeys = KeyDerivation::recordKey;
        private LongSupplier nanoClock = System::nanoTime;

        private Builder() {}

        /** Required. */
        public Builder keyProvider(KeyProvider provider) {
            this.keyProvider = provider;
            return this;
        }

        /** Required and non-empty: there is no default (spec §4.3). */
        public Builder allowedSuites(Set<Integer> suites) {
            // Not Set.copyOf, which throws on a null element before AllowList can refuse it
            // with the ConfigurationError that names it.
            this.allowedSuites = suites == null ? null : new java.util.HashSet<>(suites);
            return this;
        }

        /** Required; must be in {@link #allowedSuites}. */
        public Builder writeSuite(int suiteId) {
            this.writeSuite = suiteId;
            return this;
        }

        /** Default {@link ReadMode#STRICT}. */
        public Builder readMode(ReadMode mode) {
            this.readMode = mode;
            return this;
        }

        /**
         * spec §4.8's in-code arming form. The environment variable {@code
         * FIELDSEAL_ARM_PROVISIONAL_SUITES=1} arms too, and either is enough; both are read in
         * {@link #build}.
         */
        public Builder armProvisionalSuites(boolean arm) {
            this.armProvisionalSuites = arm;
            return this;
        }

        /** Required with {@link KeyProviders#envelope}, refused with any other provider. */
        public Builder cachePolicy(CachePolicy policy) {
            this.cachePolicy = policy;
            return this;
        }

        /**
         * Where the envelope provider's {@link Fieldseal#warm} runs its key-store and KMS calls,
         * which block (#192). Refused with any other provider, and refused if null. By default,
         * daemon threads named {@code fieldseal-warm-N}, one per {@code warm} in progress, that
         * exit when idle: never the ForkJoin common pool, whose threads the application's other
         * async work needs.
         */
        public Builder warmExecutor(Executor executor) {
            this.warmExecutor = executor;
            this.warmExecutorSet = true;
            return this;
        }

        /**
         * Where warnings go (docs/09 §2): a permissive or readonly client, and the static provider
         * outside test configuration. By default, {@link System.Logger} at {@code WARNING}.
         */
        public Builder onWarning(Consumer<String> sink) {
            this.onWarning = sink;
            return this;
        }

        /** Test seam: the environment {@link #build} reads. */
        Builder environment(Function<String, String> env) {
            this.environment = env;
            return this;
        }

        /** Test seam: how record keys are derived, so a test can see them erased. */
        Builder recordKeys(RecordKeys derive) {
            this.recordKeys = derive;
            return this;
        }

        /** Test seam: the cache's clock. */
        Builder nanoClock(LongSupplier clock) {
            this.nanoClock = clock;
            return this;
        }

        /** @throws ConfigurationError on the first setting that fails validation */
        public Fieldseal build() {
            if (keyProvider == null) {
                throw new ConfigurationError("keyProvider is required (docs/09 §2)");
            }
            if (readMode == null) {
                throw new ConfigurationError("readMode may not be null");
            }
            AllowList allow = AllowList.of(allowedSuites);
            for (int id : allow.suites()) {
                Suite s = Registry.lookup(id).orElseThrow();
                if (!s.implemented()) {
                    throw unimplemented(s, "allowedSuites");
                }
            }
            if (writeSuite == null) {
                throw new ConfigurationError("writeSuite is required (docs/09 §2)");
            }
            if (!allow.permits(writeSuite)) {
                throw new ConfigurationError(String.format("writeSuite 0x%04X is not in"
                        + " allowedSuites %s (docs/09 §2)", writeSuite, hexes(allow.suites())));
            }
            Suite write = Registry.lookup(writeSuite).orElseThrow();

            KeyProvider bound = keyProvider;
            if (keyProvider instanceof EnvelopeProvider.Unbound spec) {
                if (cachePolicy == null) {
                    throw new ConfigurationError("the envelope key provider needs a cachePolicy:"
                            + " max-age, max-uses and capacity are security parameters with no"
                            + " default (spec §5.5)");
                }
                if (warmExecutorSet && warmExecutor == null) {
                    throw new ConfigurationError("warmExecutor may not be null; leave it unset"
                            + " for the default");
                }
                bound = new EnvelopeProvider(spec, new DekCache(cachePolicy.toLimits(),
                        nanoClock), warmExecutorSet ? warmExecutor : EnvelopeProvider.WARM_POOL);
            } else if (cachePolicy != null) {
                throw new ConfigurationError("cachePolicy applies to the envelope key provider"
                        + " only; this provider would ignore it");
            } else if (warmExecutorSet) {
                throw new ConfigurationError("warmExecutor applies to the envelope key provider"
                        + " only; this provider would ignore it");
            }

            boolean armed = armProvisionalSuites
                    || "1".equals(environment.apply(SuiteProvisionalError.ARMING_VARIABLE));

            Consumer<String> warn = onWarning != null ? onWarning : Builder::log;
            if (readMode != ReadMode.STRICT) {
                warn.accept("Fieldseal client in " + readMode.name().toLowerCase(Locale.ROOT)
                        + " mode: non-envelope input is returned as-is on decrypt. Use it for"
                        + " migration or rollback windows only (spec §10.3)");
            }
            if (keyProvider instanceof KeyProviders.StaticProvider
                    && !"1".equals(environment.apply(TEST_MODE_VARIABLE))) {
                warn.accept("Fieldseal client using the static key provider outside test"
                        + " configuration: it is for tests and development only (spec §8)");
            }
            return new Fieldseal(this, bound, write, allow, armed);
        }

        /** The {@code unimplemented-registered-suite} pin: refused, naming G7. */
        private static ConfigurationError unimplemented(Suite s, String setting) {
            return new ConfigurationError(setting + " names " + s.hexId() + " (" + s.name()
                    + "), which is registered but not implemented by this core; the suite is"
                    + " unbuilt pending G7 (spec §4.2). Its envelopes are still recognized, and"
                    + " decrypting one is SUITE_NOT_ALLOWED");
        }

        private static String hexes(Set<Integer> ids) {
            return ids.stream().map(i -> String.format("0x%04X", i)).toList().toString();
        }

        private static void log(String message) {
            System.getLogger("dev.fieldseal.core").log(System.Logger.Level.WARNING, message);
        }
    }
}
