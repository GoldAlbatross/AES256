package aes

internal fun Int.ext8(offset: Int) = (this ushr offset) and 0xFF

internal fun arraycopy(src: ByteArray, srcPos: Int, dst: ByteArray, dstPos: Int, count: Int) {
    src.copyInto(dst, dstPos, srcPos, srcPos + count)
}

internal fun ByteArray.getU(offset: Int): Int = (this[offset].toInt() and 0xFF)

internal fun ByteArray.getInt(offset: Int): Int {
    return (getU(offset + 0) shl 24) or
            (getU(offset + 1) shl 16) or
            (getU(offset + 2) shl 8) or
            (getU(offset + 3) shl 0)
}

internal fun ByteArray.setInt(offset: Int, value: Int) {
    this[offset + 0] = ((value shr 24) and 0xFF).toByte()
    this[offset + 1] = ((value shr 16) and 0xFF).toByte()
    this[offset + 2] = ((value shr 8) and 0xFF).toByte()
    this[offset + 3] = ((value shr 0) and 0xFF).toByte()
}

internal fun ByteArray.toIntArray(): IntArray {
    return IntArray(size / 4)
        .also { for (n in it.indices) it[n] = getInt(n * 4) }
}

internal fun String.fromBase64(): ByteArray = Base64.decode(this)
internal val ByteArray.base64: String get() = Base64.encode(this)

internal const val KEY = "Qwe5pu/zs/ZmjSsj3aaL+OqaHCuj8ZRb"