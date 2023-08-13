package aes

@Suppress("UNUSED_CHANGED_VALUE")
internal class AES(private val keyWords: IntArray) {

    private val keySize = keyWords.size
    private val numRounds = keySize + 6
    private val ksRows = (numRounds + 1) * 4
    private val keySchedule = IntArray(ksRows).apply {
        for (ksRow in indices) {
            this[ksRow] = when {
                ksRow < keySize -> keyWords[ksRow]
                else -> {
                    var t = this[ksRow - 1]
                    if (0 == (ksRow % keySize)) {
                        t = (t shl 8) or (t ushr 24)
                        t = (SUB_BOX[t.ext8(24)] shl 24) or (SUB_BOX[t.ext8(16)] shl 16) or (SUB_BOX[t.ext8(8)] shl 8) or SUB_BOX[t and 0xff]
                        t = t xor (R_CON[(ksRow / keySize) or 0] shl 24)
                    } else if (keySize > 6 && ksRow % keySize == 4) {
                        t = (SUB_BOX[t.ext8(24)] shl 24) or (SUB_BOX[t.ext8(16)] shl 16) or (SUB_BOX[t.ext8(8)] shl 8) or SUB_BOX[t and 0xff]
                    }
                    this[ksRow - keySize] xor t
                }
            }
        }
    }
    private val invKeySchedule = IntArray(ksRows).apply {
        for (invKsRow in indices) {
            val ksRow = ksRows - invKsRow
            val t = if ((invKsRow % 4) != 0) keySchedule[ksRow] else keySchedule[ksRow - 4]
            this[invKsRow] = if (invKsRow < 4 || ksRow <= 4) t else INV_SUB_MIX_0[SUB_BOX[t.ext8(24)]] xor INV_SUB_MIX_1[SUB_BOX[t.ext8(16)]] xor INV_SUB_MIX_2[SUB_BOX[t.ext8(8)]] xor INV_SUB_MIX_3[SUB_BOX[t and 0xff]]
        }
    }

    constructor(key: ByteArray) : this(key.toIntArray())

    private fun encrypt(data: ByteArray, len: Int) {
        for (n in 0 until len step BLOCK_SIZE) encryptBlock(data, n)
    }

    private fun decrypt(data: ByteArray, len: Int) {
        for (n in 0 until len step BLOCK_SIZE) decryptBlock(data, n)
    }

    private fun encryptBlock(m: ByteArray, offset: Int) {
        this.doCryptBlock(m, offset, this.keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SUB_BOX)
    }

    private fun decryptBlock(m: ByteArray, offset: Int) {
        this.doCryptBlock(
            m, offset,
            this.invKeySchedule, INV_SUB_MIX_0, INV_SUB_MIX_1, INV_SUB_MIX_2, INV_SUB_MIX_3, INV_SUB_BOX,
            swap13 = true
        )
    }


    private fun doCryptBlock(
        m: ByteArray,
        offset: Int,
        keySchedule: IntArray,
        subMix0: IntArray,
        subMix1: IntArray,
        subMix2: IntArray,
        subMix3: IntArray,
        sBox: IntArray,
        swap13: Boolean = false
    ) {
        doCryptBlockInternal(m, offset, keySchedule, subMix0, subMix1, subMix2, subMix3, sBox, swap13,
            get = { array, o, i -> array.getInt(o + i * 4) },
            set = { array, o, i, value -> array.setInt(o + i * 4, value) },
        )
    }

    private inline fun <T> doCryptBlockInternal(
        m: T,
        offset: Int,
        keySchedule: IntArray,
        subMix0: IntArray,
        subMix1: IntArray,
        subMix2: IntArray,
        subMix3: IntArray,
        sBox: IntArray,
        swap13: Boolean = false,
        get: (m: T, offset: Int, index: Int) -> Int,
        set: (m: T, offset: Int, index: Int, value: Int) -> Unit,
    ) {
        val iO1 = if (!swap13) 1 else 3
        val iO3 = if (!swap13) 3 else 1
        var s0 = get(m, offset, 0) xor keySchedule[0]
        var s1 = get(m, offset, iO1) xor keySchedule[1]
        var s2 = get(m, offset, 2) xor keySchedule[2]
        var s3 = get(m, offset, iO3) xor keySchedule[3]
        var ksRow = 4

        for (round in 1 until numRounds) {
            val t0 = subMix0[s0.ext8(24)] xor subMix1[s1.ext8(16)] xor subMix2[s2.ext8(8)] xor subMix3[s3.ext8(0)] xor keySchedule[ksRow++]
            val t1 = subMix0[s1.ext8(24)] xor subMix1[s2.ext8(16)] xor subMix2[s3.ext8(8)] xor subMix3[s0.ext8(0)] xor keySchedule[ksRow++]
            val t2 = subMix0[s2.ext8(24)] xor subMix1[s3.ext8(16)] xor subMix2[s0.ext8(8)] xor subMix3[s1.ext8(0)] xor keySchedule[ksRow++]
            val t3 = subMix0[s3.ext8(24)] xor subMix1[s0.ext8(16)] xor subMix2[s1.ext8(8)] xor subMix3[s2.ext8(0)] xor keySchedule[ksRow++]
            s0 = t0; s1 = t1; s2 = t2; s3 = t3
        }

        val t0 = ((sBox[s0.ext8(24)] shl 24) or (sBox[s1.ext8(16)] shl 16) or (sBox[s2.ext8(8)] shl 8) or sBox[s3.ext8(0)]) xor keySchedule[ksRow++]
        val t1 = ((sBox[s1.ext8(24)] shl 24) or (sBox[s2.ext8(16)] shl 16) or (sBox[s3.ext8(8)] shl 8) or sBox[s0.ext8(0)]) xor keySchedule[ksRow++]
        val t2 = ((sBox[s2.ext8(24)] shl 24) or (sBox[s3.ext8(16)] shl 16) or (sBox[s0.ext8(8)] shl 8) or sBox[s1.ext8(0)]) xor keySchedule[ksRow++]
        val t3 = ((sBox[s3.ext8(24)] shl 24) or (sBox[s0.ext8(16)] shl 16) or (sBox[s1.ext8(8)] shl 8) or sBox[s2.ext8(0)]) xor keySchedule[ksRow++]

        set(m, offset, 0, t0)
        set(m, offset, iO1, t1)
        set(m, offset, 2, t2)
        set(m, offset, iO3, t3)
    }

    companion object {
        private val SUB_BOX = IntArray(256)
        private val INV_SUB_BOX = IntArray(256)
        private val SUB_MIX_0 = IntArray(256)
        private val SUB_MIX_1 = IntArray(256)
        private val SUB_MIX_2 = IntArray(256)
        private val SUB_MIX_3 = IntArray(256)
        private val INV_SUB_MIX_0 = IntArray(256)
        private val INV_SUB_MIX_1 = IntArray(256)
        private val INV_SUB_MIX_2 = IntArray(256)
        private val INV_SUB_MIX_3 = IntArray(256)
        private val R_CON = intArrayOf(0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)

        private const val BLOCK_SIZE = 16

        init {
            val d = IntArray(256) { if (it >= 128) (it shl 1) xor 0x11b else (it shl 1) }
            var x = 0
            var xi = 0
            for (i in 0 until 256) {
                var sx = xi xor (xi shl 1) xor (xi shl 2) xor (xi shl 3) xor (xi shl 4)
                sx = (sx ushr 8) xor (sx and 0xff) xor 0x63
                SUB_BOX[x] = sx
                INV_SUB_BOX[sx] = x
                val x2 = d[x]
                val x4 = d[x2]
                val x8 = d[x4]
                ((d[sx] * 0x101) xor (sx * 0x1010100)).also { t ->
                    SUB_MIX_0[x] = (t shl 24) or (t ushr 8)
                    SUB_MIX_1[x] = (t shl 16) or (t ushr 16)
                    SUB_MIX_2[x] = (t shl 8) or (t ushr 24)
                    SUB_MIX_3[x] = (t shl 0)
                }
                ((x8 * 0x1010101) xor (x4 * 0x10001) xor (x2 * 0x101) xor (x * 0x1010100)).also { t ->
                    INV_SUB_MIX_0[sx] = (t shl 24) or (t ushr 8)
                    INV_SUB_MIX_1[sx] = (t shl 16) or (t ushr 16)
                    INV_SUB_MIX_2[sx] = (t shl 8) or (t ushr 24)
                    INV_SUB_MIX_3[sx] = (t shl 0)
                }

                if (x == 0) {
                    x = 1; xi = 1
                } else {
                    x = x2 xor d[d[d[x8 xor x2]]]
                    xi = xi xor d[d[xi]]
                }
            }
        }

        fun encryptAesEcb(data: ByteArray, key: ByteArray): ByteArray {
            val pData = CipherPadding.addISO10126Padding(data.copyOfRange(0, data.size), BLOCK_SIZE)
            AES(key).encrypt(pData, pData.size)
            return pData
        }


        fun decryptAesEcb(data: ByteArray, key: ByteArray): ByteArray {
            val pData = data.copyOfRange(0, data.size)
            AES(key).decrypt(pData, pData.size)
            return CipherPadding.removeISO10126Padding(pData)
        }


    }
}