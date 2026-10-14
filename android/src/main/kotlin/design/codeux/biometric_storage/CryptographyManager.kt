// based on https://github.com/isaidamier/blogs.biometrics.cryptoBlog/blob/cryptoObject/app/src/main/java/com/example/android/biometricauth/CryptographyManager.kt

/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package design.codeux.biometric_storage

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.github.oshai.kotlinlogging.KotlinLogging
import java.io.File
import java.nio.charset.Charset
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

private val logger = KotlinLogging.logger {}

interface CryptographyManager {

    /**
     * RETHERA-2214: this is the RSA *public*-key cipher — never gated by biometric
     * authentication (see [getOrCreateKeyPair]'s own doc comment for why), used to wrap a
     * fresh, per-write ephemeral AES key inside [encryptData]'s envelope. Writing to storage
     * therefore never needs — and never can trigger — a BiometricPrompt.
     */
    fun getInitializedCipherForEncryption(keyName: String): Cipher

    /**
     * RETHERA-2214: this is the RSA *private*-key cipher — the one piece of this scheme that's
     * actually gated by biometric authentication (`setUserAuthenticationRequired(true)` on the
     * key pair applies only to private-key operations; see [getOrCreateKeyPair]). The
     * [encryptedDataFile]/[initializationVector] parameters are accepted for interface
     * compatibility with the call sites in [BiometricStorageFile], but are no longer needed
     * here: unlike the old single-AES-key scheme, decrypting the RSA-wrapped layer doesn't
     * need an IV read from the file up front — the actual AES-GCM IV lives inside the
     * envelope's own header and is only needed once this cipher has already unwrapped the
     * ephemeral key, inside [decryptData].
     */
    fun getInitializedCipherForDecryption(keyName: String, initializationVector: ByteArray): Cipher
    fun getInitializedCipherForDecryption(keyName: String, encryptedDataFile: File): Cipher

    /**
     * RETHERA-2214: [cipher] is the RSA public-key cipher from
     * [getInitializedCipherForEncryption]. Internally generates a fresh, one-time-use AES-256
     * key, encrypts [plaintext] with it (AES-GCM, same as before), then wraps that ephemeral
     * key with [cipher] — the standard envelope-encryption ("DEK wrapped by a KEK") pattern; see
     * https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0047/ and
     * https://github.com/authpass/biometric_storage/issues/15 for why the single-symmetric-key
     * approach this replaces can't give a write path that's structurally exempt from biometric
     * gating. Output layout: `[RSA_WRAPPED_KEY_SIZE bytes: wrapped AES key][IV_SIZE_IN_BYTES
     * bytes: AES-GCM IV][remaining bytes: AES-GCM ciphertext+tag]`.
     */
    fun encryptData(plaintext: String, cipher: Cipher): EncryptedData

    /**
     * RETHERA-2214: [cipher] is the already-BiometricPrompt-authenticated RSA private-key
     * cipher from [getInitializedCipherForDecryption] — unwraps the ephemeral AES key from the
     * front of [ciphertext], then uses it to AES-GCM decrypt the remainder. See [encryptData]
     * for the envelope layout this expects.
     */
    fun decryptData(ciphertext: ByteArray, cipher: Cipher): String

}

fun CryptographyManager(configure: KeyGenParameterSpec.Builder.() -> Unit): CryptographyManagerImpl = CryptographyManagerImpl(configure)

@Suppress("ArrayInDataClass")
data class EncryptedData(val encryptedPayload: ByteArray)

class CryptographyManagerImpl(
    private val configure: KeyGenParameterSpec.Builder.() -> Unit
) :
    CryptographyManager {

    companion object {

        // RSA-2048 is the pragmatic choice here, not a gold-plated one: OWASP's general
        // cryptographic guidance recommends 3072-bit+ RSA for key-establishment, but that's
        // aimed at keys with long-lived exposure (e.g. over a network). This key pair never
        // leaves the device, is hardware-backed where available, and only ever wraps a small
        // ephemeral AES key that's regenerated on every single write — and 3072-bit RSA support
        // in Android's StrongBox/TEE implementations is materially less consistent across OEMs
        // (Samsung/Huawei et al. — see the authpass/biometric_storage#73 discussion) than 2048,
        // which is Android's own long-standing, broadly-supported baseline for hardware-backed
        // asymmetric keys.
        private const val RSA_KEY_SIZE: Int = 2048
        private const val RSA_WRAPPED_KEY_SIZE: Int = RSA_KEY_SIZE / 8
        private const val AES_KEY_SIZE: Int = 256

        /**
         * Prefix for the key name, to distinguish it from previously written key.
         * kind of namespacing it.
         */
        private const val KEY_PREFIX = "_CM_"
        // RETHERA-2214: a distinct suffix (not reusing the old single-symmetric-key alias) so a
        // pre-upgrade install's existing AES key is never mistakenly fetched and used as if it
        // were this RSA key pair — getOrCreateKeyPair() would otherwise get a type it can't use
        // and throw. The leftover old-format key/file, if present, is cleaned up the same way
        // any other unreadable/invalidated credential already is — see decryptData's caller in
        // BiometricStorageFile.readFile().
        private const val KEY_SUFFIX_V2 = "_rsa_v2"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val ENCRYPTION_BLOCK_MODE = KeyProperties.BLOCK_MODE_GCM
        private const val ENCRYPTION_PADDING = KeyProperties.ENCRYPTION_PADDING_NONE
        private const val ENCRYPTION_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
        private const val RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"

        private const val IV_SIZE_IN_BYTES = 12
        private const val TAG_SIZE_IN_BYTES = 16

    }

    override fun getInitializedCipherForEncryption(keyName: String): Cipher {
        val keyPair = getOrCreateKeyPair(keyName)
        val cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        // Public-key operations on an asymmetric Keystore key run entirely in software, outside
        // the Keystore/TEE boundary — this never requires, and can never trigger, biometric
        // authentication, regardless of setUserAuthenticationRequired(true) on the key pair
        // (that constraint only ever applies to the private-key half). Confirmed by Android's
        // own Keystore documentation, not assumed.
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
        return cipher
    }

    override fun getInitializedCipherForDecryption(
        keyName: String,
        initializationVector: ByteArray
    ): Cipher = getInitializedCipherForDecryption(keyName)

    override fun getInitializedCipherForDecryption(
        keyName: String,
        encryptedDataFile: File,
    ): Cipher = getInitializedCipherForDecryption(keyName)

    private fun getInitializedCipherForDecryption(keyName: String): Cipher {
        val keyPair = getOrCreateKeyPair(keyName)
        val cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        // This init() call is the one that's actually gated by the key's own
        // setUserAuthenticationRequired(true)/setUserAuthenticationParameters(...) — same
        // mechanism the old symmetric key used, just now applying to the private key alone.
        cipher.init(Cipher.DECRYPT_MODE, keyPair.private)
        return cipher
    }

    override fun encryptData(plaintext: String, cipher: Cipher): EncryptedData {
        val ephemeralKey = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM).apply { init(AES_KEY_SIZE) }.generateKey()
        val aesCipher = getCipher()
        aesCipher.init(Cipher.ENCRYPT_MODE, ephemeralKey)

        val input = plaintext.toByteArray(Charsets.UTF_8)
        val aesCiphertext = aesCipher.doFinal(input)
        val iv = aesCipher.iv
        assert(iv.size == IV_SIZE_IN_BYTES)

        // RSA-OAEP can only wrap a small, fixed-size payload (far smaller than a typical
        // refresh token) — wrapping just the 32-byte ephemeral AES key, not the actual
        // plaintext, is exactly what the envelope-encryption pattern is for.
        val wrappedKey = cipher.doFinal(ephemeralKey.encoded)
        assert(wrappedKey.size == RSA_WRAPPED_KEY_SIZE)

        val ciphertext = ByteArray(wrappedKey.size + iv.size + aesCiphertext.size)
        wrappedKey.copyInto(ciphertext)
        iv.copyInto(ciphertext, wrappedKey.size)
        aesCiphertext.copyInto(ciphertext, wrappedKey.size + iv.size)

        logger.debug { "encrypted ${input.size} (${ciphertext.size} output, envelope-wrapped)" }
        return EncryptedData(ciphertext)
    }

    override fun decryptData(ciphertext: ByteArray, cipher: Cipher): String {
        logger.debug { "decrypting ${ciphertext.size} bytes (wrapped key: $RSA_WRAPPED_KEY_SIZE, iv: $IV_SIZE_IN_BYTES, tag: $TAG_SIZE_IN_BYTES)" }
        if (ciphertext.size < RSA_WRAPPED_KEY_SIZE + IV_SIZE_IN_BYTES) {
            // Too short to be a valid envelope for this scheme — almost certainly data written
            // by the old single-symmetric-key format (pre RETHERA-2214's Android RSA-envelope
            // rewrite). Treat exactly like any other unreadable/invalidated credential; the
            // caller (BiometricStorageFile.readFile()) is responsible for cleaning it up.
            throw IllegalStateException("Ciphertext too short for the current envelope format — likely a stale, incompatible format.")
        }
        val wrappedKey = ciphertext.sliceArray(0 until RSA_WRAPPED_KEY_SIZE)
        val iv = ciphertext.sliceArray(RSA_WRAPPED_KEY_SIZE until RSA_WRAPPED_KEY_SIZE + IV_SIZE_IN_BYTES)
        val aesCiphertext = ciphertext.sliceArray(RSA_WRAPPED_KEY_SIZE + IV_SIZE_IN_BYTES until ciphertext.size)

        // The one step actually gated by biometric authentication — cipher was obtained via
        // BiometricPrompt's CryptoObject flow (see BiometricStoragePlugin.authenticate()).
        val aesKeyBytes = cipher.doFinal(wrappedKey)
        val aesKey = SecretKeySpec(aesKeyBytes, ENCRYPTION_ALGORITHM)

        val aesCipher = getCipher()
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(TAG_SIZE_IN_BYTES * 8, iv))
        val plaintext = aesCipher.doFinal(aesCiphertext)
        return String(plaintext, Charset.forName("UTF-8"))
    }

    private fun getCipher(): Cipher {
        val transformation = "$ENCRYPTION_ALGORITHM/$ENCRYPTION_BLOCK_MODE/$ENCRYPTION_PADDING"
        return Cipher.getInstance(transformation)
    }

    fun deleteKey(keyName: String) {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null) // Keystore must be loaded before it can be accessed
        try {
            keyStore.deleteEntry(KEY_PREFIX + keyName + KEY_SUFFIX_V2)
        } catch (e: KeyStoreException) {
            logger.warn(e) { "Unable to delete key from KeyStore ${KEY_PREFIX}$keyName$KEY_SUFFIX_V2" }
        }
        // Best-effort cleanup of a pre-upgrade install's leftover old-format (single symmetric
        // key) entry, if any — see the KEY_SUFFIX_V2 doc comment above for why it's never used
        // for anything by this version, just tidied up when we happen to be deleting anyway.
        try {
            keyStore.deleteEntry(KEY_PREFIX + keyName)
        } catch (e: KeyStoreException) {
            logger.warn(e) { "Unable to delete legacy key from KeyStore $KEY_PREFIX$keyName" }
        }
    }

    private fun getOrCreateKeyPair(keyName: String): KeyPair {
        val realKeyName = KEY_PREFIX + keyName + KEY_SUFFIX_V2
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null) // Keystore must be loaded before it can be accessed

        val existingPrivateKey = keyStore.getKey(realKeyName, null) as? PrivateKey
        val existingPublicKey: PublicKey? = keyStore.getCertificate(realKeyName)?.publicKey
        if (existingPrivateKey != null && existingPublicKey != null) {
            return KeyPair(existingPublicKey, existingPrivateKey)
        }

        // if you reach here, then a new RSA key pair must be generated for that keyName
        val paramsBuilder = KeyGenParameterSpec.Builder(
            realKeyName,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
        paramsBuilder.apply {
            setDigests(KeyProperties.DIGEST_SHA256)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            setKeySize(RSA_KEY_SIZE)
            // RETHERA-2214: this only ever constrains the PRIVATE key's use (decrypt) — the
            // public key, once extracted via the certificate above, is usable in plain software
            // with no authentication check possible, by Android's own design (see
            // getInitializedCipherForEncryption's doc comment). The actual value (and the
            // authentication-validity window) comes from configure() below, same as the
            // original symmetric-key implementation — this placeholder is overwritten by it.
            setUserAuthenticationRequired(true)
            configure()
        }

        val keyGenParams = paramsBuilder.build()
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            ANDROID_KEYSTORE
        )
        keyPairGenerator.initialize(keyGenParams)
        return keyPairGenerator.generateKeyPair()
    }

}
