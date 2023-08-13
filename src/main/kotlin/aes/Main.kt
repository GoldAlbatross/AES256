package aes

import aes.algorithms.AES
import aes.algorithms.CipherPadding


private fun main() {

    val data1 = "date=2023.01.01 userID=63589565 time=13:08:01".toByteArray()
    val data2 = "date=2023.01.01 userID=63589565 time=13:08:01".toByteArray()
    val key = ByteArray(32) { (it % 7).toByte() }

    val encrypt = AES.encryptAesEcb(data1, key, CipherPadding.ISO10126Padding)
    val encrypt2 = AES.encryptAesEcb(data2, key, CipherPadding.ISO10126Padding)

    val decryptByte = AES.decryptAesEcb(encrypt, key, CipherPadding.ISO10126Padding)
    val decrypt = String(decryptByte, Charsets.UTF_8)

    val decryptByte2 = AES.decryptAesEcb(encrypt2, key, CipherPadding.ISO10126Padding)
    val decrypt2 = String(decryptByte2, Charsets.UTF_8)

    println("encrypted data1 -> " + String(encrypt, Charsets.UTF_8))
    println("encrypted data2 -> "  + String(encrypt2, Charsets.UTF_8))

    println("size = ${data2.size * 8}")

    println("decrypted data1 -> $decrypt")
    println("decrypted data2 -> $decrypt2")
}

