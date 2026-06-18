package pro.netcloud.trafficwrapper

import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.BarcodeFormat
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.util.EnumMap
import java.util.concurrent.atomic.AtomicBoolean

object BootstrapQrDecoder {
    private val hints: Map<DecodeHintType, Any> =
        EnumMap<DecodeHintType, Any>(DecodeHintType::class.java).apply {
            put(DecodeHintType.POSSIBLE_FORMATS, listOf(BarcodeFormat.QR_CODE))
            put(DecodeHintType.TRY_HARDER, true)
        }

    fun decode(source: LuminanceSource): String? {
        val reader = MultiFormatReader()
        reader.setHints(hints)
        return try {
            reader.decodeWithState(BinaryBitmap(HybridBinarizer(source))).text
        } catch (_: NotFoundException) {
            null
        } finally {
            reader.reset()
        }
    }

    fun decodeRgb(width: Int, height: Int, pixels: IntArray): String? =
        decode(RGBLuminanceSource(width, height, pixels))
}

class BootstrapQrAnalyzer(
    private val onQrFound: (String) -> Unit,
) : ImageAnalysis.Analyzer {
    private val consumed = AtomicBoolean(false)

    override fun analyze(image: ImageProxy) {
        try {
            if (consumed.get()) return
            val bytes = compactYPlane(image)
            val source = PlanarYUVLuminanceSource(
                bytes,
                image.width,
                image.height,
                0,
                0,
                image.width,
                image.height,
                false,
            )
            val text = BootstrapQrDecoder.decode(source)
            if (text != null && consumed.compareAndSet(false, true)) {
                onQrFound(text)
            }
        } finally {
            image.close()
        }
    }

    private fun compactYPlane(image: ImageProxy): ByteArray {
        val yPlane = image.planes.firstOrNull() ?: return ByteArray(0)
        val width = image.width
        val height = image.height
        val rowStride = yPlane.rowStride
        val pixelStride = yPlane.pixelStride
        val buffer = yPlane.buffer.duplicate()
        val output = ByteArray(width * height)
        val row = ByteArray(rowStride)
        for (y in 0 until height) {
            val rowStart = y * rowStride
            if (rowStart >= buffer.limit()) break
            buffer.position(rowStart)
            val bytesToRead = minOf(rowStride, buffer.remaining())
            buffer.get(row, 0, bytesToRead)
            for (x in 0 until width) {
                val rowIndex = x * pixelStride
                if (rowIndex < bytesToRead) {
                    output[y * width + x] = row[rowIndex]
                }
            }
        }
        return output
    }
}
