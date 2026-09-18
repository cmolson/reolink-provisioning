package dev.cmolabs.reolinkble

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Crypto and TLV framing for Reolink's BLE provisioning protocol, written up in
 * PROTOCOL.md. No Android APIs in here, so it unit tests off-device.
 *
 * A message is `[uint32_le totalLen][payload]`, and the payload is one or more
 * TLVs of `[uint32_le type][uint32_le len][value]`, little-endian throughout.
 * Everything is plaintext until the handshake finishes, after which the Wi-Fi
 * command is AES-128-CFB encrypted.
 */
object ReolinkBleCrypto {

    const val CURVE = "secp256r1"

    // Handshake TLV types.
    const val TLV_ENCRYPT_VERSION = 1
    const val TLV_RANDOM1 = 2
    const val TLV_SERVER_PUBLIC_KEY = 3
    const val TLV_RANDOM2 = 4
    const val TLV_CLIENT_PUBLIC_KEY = 5
    const val TLV_MTU = 6

    /** TLV type carrying the encrypted Wi-Fi config JSON. */
    const val TLV_CONFIG_WIFI = 100001

    const val ENCRYPT_VERSION = 1
    const val PBKDF2_ITERATIONS = 10000
    const val DERIVED_KEY_BYTES = 32 // 16-byte AES key || 16-byte IV
    const val APP_RANDOM_BYTES = 64
    const val UNCOMPRESSED_POINT_BYTES = 65 // 0x04 || X[32] || Y[32]
    private const val COORD_BYTES = 32

    /** Little-endian 4-byte encoding of [value] (matches the app's intToByteArray). */
    fun le32(value: Int): ByteArray = byteArrayOf(
        (value and 0xFF).toByte(),
        ((value ushr 8) and 0xFF).toByte(),
        ((value ushr 16) and 0xFF).toByte(),
        ((value ushr 24) and 0xFF).toByte(),
    )

    fun readLe32(buf: ByteArray, offset: Int): Int =
        (buf[offset].toInt() and 0xFF) or
            ((buf[offset + 1].toInt() and 0xFF) shl 8) or
            ((buf[offset + 2].toInt() and 0xFF) shl 16) or
            ((buf[offset + 3].toInt() and 0xFF) shl 24)

    /** Build a single TLV: `[type le32][len le32][value]`. */
    fun tlv(type: Int, value: ByteArray): ByteArray = le32(type) + le32(value.size) + value

    /** Prepend the 4-byte little-endian length the transport uses for reassembly. */
    fun frame(payload: ByteArray): ByteArray = le32(payload.size) + payload

    data class Tlv(val type: Int, val value: ByteArray)

    /** Parse concatenated TLVs; stops cleanly on any short/truncated trailer. */
    fun parseTlvs(buf: ByteArray): List<Tlv> {
        val out = ArrayList<Tlv>()
        var i = 0
        while (i + 8 <= buf.size) {
            val type = readLe32(buf, i)
            val len = readLe32(buf, i + 4)
            val start = i + 8
            if (len < 0 || start + len > buf.size) break
            out.add(Tlv(type, buf.copyOfRange(start, start + len)))
            i = start + len
        }
        return out
    }

    fun generateKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec(CURVE))
        }.generateKeyPair()

    private fun ecParameterSpec(): ECParameterSpec =
        AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec(CURVE))
            getParameterSpec(ECParameterSpec::class.java)
        }

    /** Encode an EC public key as the 65-byte uncompressed point `0x04 || X || Y`. */
    fun encodePublicKey(publicKey: ECPublicKey): ByteArray {
        val out = ByteArray(UNCOMPRESSED_POINT_BYTES)
        out[0] = 0x04
        writeFixed(publicKey.w.affineX, out, 1)
        writeFixed(publicKey.w.affineY, out, 1 + COORD_BYTES)
        return out
    }

    /** Decode a 65-byte uncompressed point into an EC public key on [CURVE]. */
    private fun decodePublicKey(uncompressed: ByteArray): ECPublicKey {
        require(uncompressed.size == UNCOMPRESSED_POINT_BYTES && uncompressed[0] == 0x04.toByte()) {
            "expected 65-byte uncompressed point"
        }
        val x = BigInteger(1, uncompressed.copyOfRange(1, 1 + COORD_BYTES))
        val y = BigInteger(1, uncompressed.copyOfRange(1 + COORD_BYTES, UNCOMPRESSED_POINT_BYTES))
        val spec = ECPublicKeySpec(ECPoint(x, y), ecParameterSpec())
        return KeyFactory.getInstance("EC").generatePublic(spec) as ECPublicKey
    }

    /** ECDH shared secret (32-byte X coordinate) with the camera's public key. */
    fun sharedSecret(appPrivate: PrivateKey, devicePublicKey: ByteArray): ByteArray =
        KeyAgreement.getInstance("ECDH").run {
            init(appPrivate)
            doPhase(decodePublicKey(devicePublicKey), true)
            generateSecret()
        }

    /**
     * Derive the AES key and IV exactly as the camera does: PBKDF2-HMAC-SHA256
     * with the two randoms as the password and the ECDH shared secret as the
     * salt, then split 32 bytes into `key = out[0..16)` and `iv = out[16..32)`.
     */
    fun deriveKeyIv(deviceRandom1: ByteArray, appRandom2: ByteArray, shared: ByteArray): Pair<ByteArray, ByteArray> {
        val okm = pbkdf2HmacSha256(deviceRandom1 + appRandom2, shared, PBKDF2_ITERATIONS, DERIVED_KEY_BYTES)
        return okm.copyOfRange(0, 16) to okm.copyOfRange(16, 32)
    }

    fun aesCfbEncrypt(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray =
        aesCfb(Cipher.ENCRYPT_MODE, data, key, iv)

    fun aesCfbDecrypt(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray =
        aesCfb(Cipher.DECRYPT_MODE, data, key, iv)

    private fun aesCfb(mode: Int, data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray =
        Cipher.getInstance("AES/CFB/NoPadding").run {
            init(mode, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            doFinal(data)
        }

    /**
     * PBKDF2-HMAC-SHA256 over a raw byte[] password. Done by hand on HmacSHA256
     * because JCE's PBEKeySpec only takes a char[], which mangles binary input.
     */
    fun pbkdf2HmacSha256(password: ByteArray, salt: ByteArray, iterations: Int, dkLen: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(password, "HmacSHA256")) }
        val hLen = mac.macLength
        val out = ByteArray(dkLen)
        var offset = 0
        var blockIndex = 1
        while (offset < dkLen) {
            mac.update(salt)
            var u = mac.doFinal(le32be(blockIndex))
            val t = u.copyOf()
            repeat(iterations - 1) {
                u = mac.doFinal(u)
                for (k in t.indices) t[k] = (t[k].toInt() xor u[k].toInt()).toByte()
            }
            val take = minOf(hLen, dkLen - offset)
            System.arraycopy(t, 0, out, offset, take)
            offset += take
            blockIndex++
        }
        return out
    }

    private fun le32be(value: Int): ByteArray = byteArrayOf(
        ((value ushr 24) and 0xFF).toByte(),
        ((value ushr 16) and 0xFF).toByte(),
        ((value ushr 8) and 0xFF).toByte(),
        (value and 0xFF).toByte(),
    )

    /** Big-endian, left-zero-padded (or high-byte-trimmed) fixed 32-byte coordinate. */
    private fun writeFixed(value: BigInteger, dest: ByteArray, at: Int) {
        val raw = value.toByteArray() // may have a leading 0x00 sign byte or be short
        val src = when {
            raw.size == COORD_BYTES -> raw
            raw.size > COORD_BYTES -> raw.copyOfRange(raw.size - COORD_BYTES, raw.size)
            else -> ByteArray(COORD_BYTES).also { System.arraycopy(raw, 0, it, COORD_BYTES - raw.size, raw.size) }
        }
        System.arraycopy(src, 0, dest, at, COORD_BYTES)
    }
}
