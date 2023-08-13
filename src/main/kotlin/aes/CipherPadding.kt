package aes

import kotlin.random.Random

internal class CipherPadding {

    companion object {
        fun addISO10126Padding(data: ByteArray, blockSize: Int): ByteArray {
            val paddingSize = blockSize - data.size % blockSize
            val result = ByteArray(data.size + paddingSize)
            arraycopy(data, 0, result, 0, data.size)

            val randomBytes = ByteArray(paddingSize)
            Random.nextBytes(randomBytes)
            randomBytes[paddingSize - 1] = paddingSize.toByte()

            arraycopy(randomBytes, 0, result, data.size, randomBytes.size)
            return result
        }

        fun removeISO10126Padding(data: ByteArray): ByteArray {
            val paddingSize = data[data.size - 1].toInt() and 0xFF
            return data.copyOf(data.size - paddingSize)
        }
    }
}

