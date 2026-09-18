package dev.cmolabs.reolinkble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import timber.log.Timber
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.util.UUID
import kotlin.coroutines.resume

private const val TAG = "ReolinkBleProvisioner"

private val SERVICE_UUID: UUID = UUID.fromString("3d24bfff-0bcb-08bd-e5fc-0647025b2dce")
private val CHAR_UUID: UUID = UUID.fromString("0000aaaa-0000-1000-8000-00805f9b34fb")
private val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

/** Advertised name prefix of a Reolink camera in setup mode, e.g. "Reolink_t1olgEqn…". */
private const val DEVICE_NAME_PREFIX = "Reolink"

private const val REQUESTED_MTU = 247
private const val DEFAULT_MTU = 23
private const val SCAN_TIMEOUT_MS = 20_000L

/**
 * Pause between stopping the scan and connecting. Android's BLE stack commonly
 * fails a connect issued immediately out of a scan callback (status 133).
 */
private const val SCAN_SETTLE_MS = 600L
private const val OP_TIMEOUT_MS = 90_000L

/**
 * How long to wait for the camera's acknowledgement of the Wi-Fi command. A
 * factory-fresh camera can take a while to test the network, and some units join
 * and tear their BLE stack down without ever replying — so a missing ack is not
 * proof of failure (the camera showing up as a hotspot client is).
 */
private const val CONFIG_REPLY_TIMEOUT_MS = 45_000L
private const val WIFI_RESULT_OK = 0

/**
 * Provisions a Reolink camera (e.g. E1 Pro) onto a Wi-Fi network over BLE — the
 * path for models whose setup uses Bluetooth rather than the lens-QR flow. See
 * `PROTOCOL.md` and [ReolinkBleCrypto].
 *
 * Scans for a camera advertising a "Reolink" name (these cameras do NOT put the
 * vendor service UUID in their advertisement, so the service is verified after
 * connecting), performs the plaintext ECDH handshake, derives the AES-128-CFB
 * session key, then sends the encrypted `WIFI_TEST_AND_SET` (cmd 4) command. A
 * camera in setup mode must be advertising for this to find it.
 */
@Suppress("MagicNumber", "ReturnCount")
class ReolinkBleProvisioner(
    private val context: Context,
) {
    private val bluetoothManager: BluetoothManager? =
        context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager

    /**
     * Find the first Reolink camera advertising the provisioning service and set
     * its Wi-Fi credentials. Returns true only when the camera reports the
     * configuration succeeded.
     */
    @SuppressLint("MissingPermission")
    suspend fun provisionFirstAvailable(ssid: String, password: String, country: String): Boolean {
        val adapter = bluetoothManager?.adapter
        if (adapter == null || !adapter.isEnabled) {
            Timber.w("$TAG: Bluetooth unavailable or disabled")
            return false
        }
        if (ssid.isBlank()) {
            Timber.w("$TAG: refusing to provision with a blank SSID")
            return false
        }
        val device = scanForCamera(adapter) ?: run {
            Timber.i("$TAG: no Reolink camera found advertising the provisioning service")
            return false
        }
        Timber.i("$TAG: provisioning ${device.address} onto '$ssid'")
        delay(SCAN_SETTLE_MS)
        return withTimeoutOrNull(OP_TIMEOUT_MS) {
            Session(device).run(ssid, password, country)
        } ?: run {
            Timber.w("$TAG: provisioning timed out for ${device.address}")
            false
        }
    }

    @SuppressLint("MissingPermission")
    private suspend fun scanForCamera(adapter: BluetoothAdapter): BluetoothDevice? {
        val scanner = adapter.bluetoothLeScanner ?: return null
        var activeCallback: ScanCallback? = null
        return try {
            withTimeoutOrNull(SCAN_TIMEOUT_MS) {
                suspendCancellableCoroutine { cont ->
                    val callback = object : ScanCallback() {
                        override fun onScanResult(callbackType: Int, result: ScanResult) {
                            val name = result.device?.name ?: result.scanRecord?.deviceName
                            if (name?.startsWith(DEVICE_NAME_PREFIX, ignoreCase = true) != true) return
                            if (cont.isActive) cont.resume(result.device)
                        }

                        override fun onScanFailed(errorCode: Int) {
                            Timber.w("$TAG: BLE scan failed, code=$errorCode")
                            if (cont.isActive) cont.resume(null)
                        }
                    }
                    activeCallback = callback
                    // These cameras advertise a name but NOT the vendor service
                    // UUID, so a service-UUID scan filter never matches. Scan
                    // unfiltered and match the name; the service itself is
                    // verified after connecting (see onServicesDiscovered).
                    val settings = ScanSettings.Builder()
                        .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
                    scanner.startScan(null, settings, callback)
                    cont.invokeOnCancellation { runCatching { scanner.stopScan(callback) } }
                }
            }
        } finally {
            activeCallback?.let { cb -> runCatching { scanner.stopScan(cb) } }
        }
    }

    /** One connect→handshake→configure exchange with a single camera. */
    @SuppressLint("MissingPermission")
    private inner class Session(private val device: BluetoothDevice) {
        private val ready = CompletableDeferred<Boolean>()
        private val messages = Channel<ByteArray>(Channel.UNLIMITED)
        private val writeMutex = Mutex()
        @Volatile private var writeAck: CompletableDeferred<Boolean>? = null
        @Volatile private var gatt: BluetoothGatt? = null
        @Volatile private var mtu = DEFAULT_MTU

        // This stack negotiates the MTU on connect, so onMtuChanged can land
        // before services are discovered. Notifications must not be set up
        // until the service is actually there.
        @Volatile private var servicesReady = false

        // Reassembly of device->app frames: [uint32_le totalLen][payload...].
        private var need = 0
        private val rx = ArrayList<Byte>()

        private val callback = object : BluetoothGattCallback() {
            override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
                Timber.d("$TAG: ${device.address} connectionStateChange status=$status state=$newState")
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    g.discoverServices()
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    if (!ready.isCompleted) {
                        Timber.w("$TAG: ${device.address} disconnected before ready, status=$status")
                        ready.complete(false)
                    }
                    messages.close()
                }
            }

            override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
                val found = characteristic(g) != null
                Timber.d("$TAG: ${device.address} servicesDiscovered status=$status char=$found")
                if (status != BluetoothGatt.GATT_SUCCESS || !found) {
                    completeNotReady(); return
                }
                servicesReady = true
                // Ask for a bigger MTU, but don't depend on the callback: if the
                // request can't be issued, carry on at whatever we already have.
                if (!g.requestMtu(REQUESTED_MTU)) enableNotifications(g)
            }

            override fun onMtuChanged(g: BluetoothGatt, newMtu: Int, status: Int) {
                Timber.d("$TAG: ${device.address} mtuChanged mtu=$newMtu status=$status")
                if (status == BluetoothGatt.GATT_SUCCESS && newMtu >= DEFAULT_MTU) mtu = newMtu
                // An MTU exchange the stack started itself can arrive before
                // service discovery; ignore those.
                if (servicesReady) enableNotifications(g)
            }

            @Suppress("DEPRECATION")
            private fun enableNotifications(g: BluetoothGatt) {
                val ch = characteristic(g) ?: run { completeNotReady(); return }
                g.setCharacteristicNotification(ch, true)
                val cccd = ch.getDescriptor(CCCD_UUID) ?: run {
                    Timber.w("$TAG: ${device.address} characteristic has no CCCD")
                    completeNotReady(); return
                }
                cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                if (!g.writeDescriptor(cccd)) {
                    Timber.w("$TAG: ${device.address} writeDescriptor refused")
                    completeNotReady()
                }
            }

            override fun onDescriptorWrite(g: BluetoothGatt, d: BluetoothGattDescriptor, status: Int) {
                if (d.uuid != CCCD_UUID) return
                Timber.d("$TAG: ${device.address} notifications enabled, status=$status")
                ready.complete(status == BluetoothGatt.GATT_SUCCESS)
            }

            override fun onCharacteristicWrite(
                g: BluetoothGatt, ch: BluetoothGattCharacteristic, status: Int
            ) {
                writeAck?.complete(status == BluetoothGatt.GATT_SUCCESS)
            }

            @Suppress("DEPRECATION")
            override fun onCharacteristicChanged(g: BluetoothGatt, ch: BluetoothGattCharacteristic) {
                if (ch.uuid == CHAR_UUID) onInbound(ch.value ?: ByteArray(0))
            }

            private fun completeNotReady() {
                if (!ready.isCompleted) ready.complete(false)
            }
        }

        private fun characteristic(g: BluetoothGatt): BluetoothGattCharacteristic? =
            g.getService(SERVICE_UUID)?.getCharacteristic(CHAR_UUID)

        /** Accumulate a notification and emit whole logical messages. */
        private fun onInbound(data: ByteArray) {
            for (b in data) rx.add(b)
            while (true) {
                if (need == 0) {
                    if (rx.size < 4) return
                    need = ReolinkBleCrypto.readLe32(rx.take(4).toByteArray(), 0)
                    repeat(4) { rx.removeAt(0) }
                }
                if (rx.size < need) return
                val msg = ByteArray(need) { rx[it] }
                repeat(need) { rx.removeAt(0) }
                need = 0
                messages.trySend(msg)
            }
        }

        suspend fun run(ssid: String, password: String, country: String): Boolean {
            gatt = device.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE)
            try {
                if (ready.await() != true) {
                    Timber.w("$TAG: GATT not ready for ${device.address}")
                    return false
                }
                handshake()
                return sendWifiConfig(ssid, password, country)
            } catch (e: Exception) {
                Timber.e(e, "$TAG: provisioning failed for ${device.address}")
                return false
            } finally {
                runCatching { gatt?.disconnect() }
                runCatching { gatt?.close() }
                messages.close()
            }
        }

        private suspend fun handshake() {
            // 1. announce encryption version + negotiated MTU (plaintext)
            sendFrame(
                ReolinkBleCrypto.tlv(
                    ReolinkBleCrypto.TLV_ENCRYPT_VERSION,
                    ReolinkBleCrypto.le32(ReolinkBleCrypto.ENCRYPT_VERSION)
                ) + ReolinkBleCrypto.tlv(ReolinkBleCrypto.TLV_MTU, ReolinkBleCrypto.le32(mtu))
            )

            // 2. receive the device random and public key
            var deviceRandom1: ByteArray? = null
            var devicePublicKey: ByteArray? = null
            while (devicePublicKey == null) {
                for (t in ReolinkBleCrypto.parseTlvs(messages.receive())) when (t.type) {
                    ReolinkBleCrypto.TLV_RANDOM1 -> deviceRandom1 = t.value
                    ReolinkBleCrypto.TLV_SERVER_PUBLIC_KEY -> devicePublicKey = t.value
                }
            }
            requireNotNull(deviceRandom1) { "device sent no random1" }

            // 3. send our random and public key
            val keyPair = ReolinkBleCrypto.generateKeyPair()
            val appPublicKey = ReolinkBleCrypto.encodePublicKey(keyPair.public as ECPublicKey)
            val appRandom2 = ByteArray(ReolinkBleCrypto.APP_RANDOM_BYTES)
                .also { SecureRandom().nextBytes(it) }
            sendFrame(
                ReolinkBleCrypto.tlv(ReolinkBleCrypto.TLV_RANDOM2, appRandom2) +
                    ReolinkBleCrypto.tlv(ReolinkBleCrypto.TLV_CLIENT_PUBLIC_KEY, appPublicKey)
            )

            // 4. derive the session key/iv
            val shared = ReolinkBleCrypto.sharedSecret(keyPair.private, devicePublicKey!!)
            val (key, iv) = ReolinkBleCrypto.deriveKeyIv(deviceRandom1!!, appRandom2, shared)
            aesKey = key
            aesIv = iv
            Timber.i("$TAG: handshake complete with ${device.address}")
        }

        private lateinit var aesKey: ByteArray
        private lateinit var aesIv: ByteArray

        private suspend fun sendWifiConfig(ssid: String, password: String, country: String): Boolean {
            val json = JSONObject()
                .put("cmd", 4) // WIFI_TEST_AND_SET
                .put("id", 1)
                .put("data", JSONObject().put("s", ssid).put("p", password).put("c", country))
                .toString()
            val inner = ReolinkBleCrypto.tlv(ReolinkBleCrypto.TLV_CONFIG_WIFI, json.toByteArray(Charsets.UTF_8))
            sendFrame(ReolinkBleCrypto.aesCfbEncrypt(inner, aesKey, aesIv))

            val reply = withTimeoutOrNull(CONFIG_REPLY_TIMEOUT_MS) { messages.receive() }
            if (reply == null) {
                Timber.w(
                    "$TAG: ${device.address} sent Wi-Fi config but got no acknowledgement — " +
                        "it may have joined anyway, check the AP client list"
                )
                return false
            }
            val response = ReolinkBleCrypto.aesCfbDecrypt(reply, aesKey, aesIv)
            val success = ReolinkBleCrypto.parseTlvs(response).any { tlv ->
                tlv.type == ReolinkBleCrypto.TLV_CONFIG_WIFI && isConfigSuccess(tlv.value)
            }
            Timber.i("$TAG: ${device.address} Wi-Fi config success=$success")
            return success
        }

        private fun isConfigSuccess(value: ByteArray): Boolean = runCatching {
            val data = JSONObject(String(value, Charsets.UTF_8)).optJSONObject("data")
            data != null &&
                data.optInt("code", -1) == WIFI_RESULT_OK &&
                data.optInt("result", -1) == WIFI_RESULT_OK
        }.getOrDefault(false)

        /** Write a length-prefixed frame, split into MTU-sized chunks. */
        private suspend fun sendFrame(payload: ByteArray) {
            val frame = ReolinkBleCrypto.frame(payload)
            val g = gatt ?: return
            val ch = characteristic(g) ?: return
            val chunk = (mtu - 3).coerceAtLeast(DEFAULT_MTU - 3)
            var offset = 0
            while (offset < frame.size) {
                val end = minOf(offset + chunk, frame.size)
                writeChunk(g, ch, frame.copyOfRange(offset, end))
                offset = end
            }
        }

        @Suppress("DEPRECATION")
        private suspend fun writeChunk(
            g: BluetoothGatt, ch: BluetoothGattCharacteristic, bytes: ByteArray
        ) = writeMutex.withLock {
            val ack = CompletableDeferred<Boolean>()
            writeAck = ack
            ch.value = bytes
            ch.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            if (!g.writeCharacteristic(ch)) {
                writeAck = null
                error("writeCharacteristic returned false")
            }
            val ok = ack.await()
            writeAck = null
            if (!ok) error("characteristic write failed")
        }
    }
}
