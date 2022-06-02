package com.rlatapy.sandbox

import android.app.Activity
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.security.auth.DestroyFailedException

class MainActivity : Activity() {

    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        this.load(null)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val generator: KeyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEY_STORE_PROVIDER
        )
        generator.init(
            KeyGenParameterSpec.Builder(
                AES_LOCAL_PROTECTION_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setKeySize(AES_GCM_KEY_SIZE_IN_BITS)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
        )
        val newSecretKey = generator.generateKey()

        try {
            newSecretKey.destroy()
        } catch (e: DestroyFailedException) {
            // Destroy not implemented
        } catch (e: NoSuchMethodError) {
            // Destroy not implemented
        }
    }

    companion object {
        const val ANDROID_KEY_STORE_PROVIDER: String = "AndroidKeyStore"
        private const val AES_GCM_KEY_SIZE_IN_BITS = 128
        private const val AES_LOCAL_PROTECTION_KEY_ALIAS = "aes_local_protection"
    }
}