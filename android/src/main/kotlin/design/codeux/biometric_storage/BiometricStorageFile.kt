package design.codeux.biometric_storage

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyProperties
import android.util.Log
import io.github.oshai.kotlinlogging.KotlinLogging
import java.io.File
import java.io.IOException
import java.security.GeneralSecurityException
import javax.crypto.Cipher

private val logger = KotlinLogging.logger {}

data class InitOptions(
    val authenticationValidityDurationSeconds: Int = -1,
    val authenticationRequired: Boolean = true,
    val androidBiometricOnly: Boolean = true
)

class BiometricStorageFile(
    context: Context,
    baseName: String,
    val options: InitOptions
) {

    companion object {
        /**
         * Name of directory inside private storage where all encrypted files are stored.
         */
        private const val DIRECTORY_NAME = "biometric_storage"
        private const val FILE_SUFFIX_V2 = ".v2.txt"
    }

    private val masterKeyName = "${baseName}_master_key"
    private val fileNameV2 = "$baseName$FILE_SUFFIX_V2"
    private val fileV2: File

    private val cryptographyManager = CryptographyManager {
        setUserAuthenticationRequired(options.authenticationRequired)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val useStrongBox = context.packageManager.hasSystemFeature(
                PackageManager.FEATURE_STRONGBOX_KEYSTORE
            )
            setIsStrongBoxBacked(useStrongBox)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (options.authenticationValidityDurationSeconds == -1) {
                setUserAuthenticationParameters(
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG
                )
            } else {
                setUserAuthenticationParameters(
                    options.authenticationValidityDurationSeconds,
                    KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG
                )
            }
        } else {
            @Suppress("DEPRECATION")
            setUserAuthenticationValidityDurationSeconds(options.authenticationValidityDurationSeconds)
        }
    }

    init {
        val baseDir = File(context.filesDir, DIRECTORY_NAME)
        if (!baseDir.exists()) {
            baseDir.mkdirs()
        }
        fileV2 = File(baseDir, fileNameV2)

        logger.trace { "Initialized $this with $options" }

        validateOptions()
    }

    private fun validateOptions() {
        if (options.authenticationValidityDurationSeconds == -1 && !options.androidBiometricOnly) {
            throw IllegalArgumentException("when authenticationValidityDurationSeconds is -1, androidBiometricOnly must be true")
        }
    }

    fun cipherForEncrypt() = cryptographyManager.getInitializedCipherForEncryption(masterKeyName)
    fun cipherForDecrypt(): Cipher? {
        if (fileV2.exists()) {
            return cryptographyManager.getInitializedCipherForDecryption(masterKeyName, fileV2)
        }
        logger.debug { "No file exists, no IV found. null cipher." }
        return null
    }

    fun exists() = fileV2.exists()

    @Synchronized
    fun writeFile(cipher: Cipher?, content: String) {
        // cipher will be null if user does not need authentication or valid period is > -1
        val useCipher = cipher ?: cipherForEncrypt()
        Log.e("RETHERA_DEBUG", "writeFile: masterKeyName=$masterKeyName path=$fileV2")
        try {
            val encrypted = cryptographyManager.encryptData(content, useCipher)
            fileV2.writeBytes(encrypted.encryptedPayload)
            Log.e("RETHERA_DEBUG", "writeFile: wrote ${encrypted.encryptedPayload.size} bytes to $fileV2")
            logger.debug { "Successfully written ${encrypted.encryptedPayload.size} bytes." }

            return
        } catch (ex: IOException) {
            // Error occurred opening file for writing.
            logger.error(ex) { "Error while writing encrypted file $fileV2" }
            throw ex
        }
    }

    @Synchronized
    fun readFile(cipher: Cipher?): String? {
        val useCipher = cipher ?: cipherForDecrypt()
        Log.e("RETHERA_DEBUG", "readFile: masterKeyName=$masterKeyName useCipher=${useCipher != null} fileExists=${fileV2.exists()} path=$fileV2")
        // if the file exists, there should *always* be a decryption key.
        if (useCipher != null && fileV2.exists()) {
            return try {
                val bytes = fileV2.readBytes()
                Log.e("RETHERA_DEBUG", "readFile: read ${bytes.size} bytes, about to decrypt")
                logger.debug { "read ${bytes.size}" }
                val result = cryptographyManager.decryptData(bytes, useCipher)
                Log.e("RETHERA_DEBUG", "readFile: decrypt SUCCEEDED, result length=${result.length}")
                result
            } catch (ex: IOException) {
                Log.e("RETHERA_DEBUG", "readFile: IOException during decrypt", ex)
                logger.error(ex) { "Error while writing encrypted file $fileV2" }
                null
            } catch (ex: GeneralSecurityException) {
                Log.e("RETHERA_DEBUG", "readFile: GeneralSecurityException (${ex.javaClass.simpleName}): ${ex.message}", ex)
                // RETHERA-2214: the stored bytes don't decrypt under the current scheme — most
                // likely a pre-upgrade install's data written under an older, incompatible
                // envelope format (e.g. before the Android RSA-envelope rewrite). There is no
                // way to recover data that doesn't decrypt under the key/format we now have —
                // the standard, documented approach for Keystore-protected data in this
                // situation is to treat it the same as any other unreadable/invalidated
                // credential: delete it and let the normal "credential not available" fallback
                // take over (same as KeyPermanentlyInvalidatedException elsewhere in this file).
                logger.warn(ex) { "Stored data for $fileV2 could not be decrypted under the current format — treating as stale, deleting." }
                deleteFile()
                null
            } catch (ex: IllegalStateException) {
                Log.e("RETHERA_DEBUG", "readFile: IllegalStateException: ${ex.message}", ex)
                // Thrown by CryptographyManagerImpl.decryptData() when the ciphertext is too
                // short to be a valid envelope at all — same stale-format situation as above.
                logger.warn(ex) { "Stored data for $fileV2 has an unrecognized format — treating as stale, deleting." }
                deleteFile()
                null
            }
        }

        Log.e("RETHERA_DEBUG", "readFile: falling through to null (useCipher=${useCipher != null}, fileExists=${fileV2.exists()})")
        logger.debug { "File $fileV2 does not exist. returning null." }
        return null

    }

    @Synchronized
    fun deleteFile(): Boolean {
        cryptographyManager.deleteKey(masterKeyName)
        return fileV2.delete()
    }

    override fun toString(): String {
        return "BiometricStorageFile(masterKeyName='$masterKeyName', fileName='$fileNameV2', file=$fileV2)"
    }

    fun dispose() {
        logger.trace { "dispose" }
    }

}
