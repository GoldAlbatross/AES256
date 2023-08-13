package aes

internal object Base64 {
    private const val TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    private val DECODE = TABLE.toDecodeArray()

    fun decode(str: String, url: Boolean = false): ByteArray {
        val src = ByteArray(str.length) { str[it].code.toByte() }
        val dst = ByteArray(src.size)
        return dst.copyOf(decode(src, dst, url))
    }

    private fun decode(src: ByteArray, dst: ByteArray, url: Boolean = false): Int {
        val decodeArray = DECODE

        var m = 0
        var n = 0
        while (n < src.size) {
            val d = decodeArray[src.readU8(n)]
            if (d < 0) {
                n++
                continue // skip character
            }

            val b0 = if (n < src.size) decodeArray[src.readU8(n++)] else 64
            val b1 = if (n < src.size) decodeArray[src.readU8(n++)] else 64
            val b2 = if (n < src.size) decodeArray[src.readU8(n++)] else 64
            val b3 = if (n < src.size) decodeArray[src.readU8(n++)] else 64
            dst[m++] = (b0 shl 2 or (b1 shr 4)).toByte()
            if (b2 < 64) {
                dst[m++] = (b1 shl 4 or (b2 shr 2)).toByte()
                if (b3 < 64) {
                    dst[m++] = (b2 shl 6 or b3).toByte()
                }
            }
        }
        return m
    }

    @Suppress("UNUSED_CHANGED_VALUE")
    fun encode(src: ByteArray, url: Boolean = false, doPadding: Boolean = false): String {
        val encodeTable = TABLE

        val out = StringBuilder((src.size * 4) / 3 + 4)
        var ipos = 0
        val extraBytes = src.size % 3
        while (ipos < src.size - 2) {
            val num = src.readU24BE(ipos)
            ipos += 3

            out.append(encodeTable[(num ushr 18) and 0x3F])
            out.append(encodeTable[(num ushr 12) and 0x3F])
            out.append(encodeTable[(num ushr 6) and 0x3F])
            out.append(encodeTable[(num ushr 0) and 0x3F])
        }

        if (extraBytes == 1) {
            val num = src.readU8(ipos++)
            out.append(encodeTable[num ushr 2])
            out.append(encodeTable[(num shl 4) and 0x3F])
            if (!url || (url && doPadding)) {
                out.append('=')
                out.append('=')
            }
        } else if (extraBytes == 2) {
            val tmp = (src.readU8(ipos++) shl 8) or src.readU8(ipos++)
            out.append(encodeTable[tmp ushr 10])
            out.append(encodeTable[(tmp ushr 4) and 0x3F])
            out.append(encodeTable[(tmp shl 2) and 0x3F])
            if (!url || (url && doPadding)) {
                out.append('=')
            }
        }

        return out.toString()
    }

    private fun ByteArray.readU8(index: Int): Int = this[index].toInt() and 0xFF
    private fun ByteArray.readU24BE(index: Int): Int =
        (readU8(index + 0) shl 16) or (readU8(index + 1) shl 8) or (readU8(index + 2) shl 0)

    private fun String.toDecodeArray(): IntArray = IntArray(0x100).also {
        for (n in 0..255) it[n] = -1
        for (n in indices) {
            it[this[n].code] = n
        }
    }
}
