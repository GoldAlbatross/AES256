package aes


fun main() {

    val apiKey = "2023-08-01/63589563".toByteArray()
    val key = KEY.toByteArray()

    val encrypt = AES.encryptAesEcb(apiKey, key).base64
    val decryptByte = AES.decryptAesEcb(encrypt.fromBase64(), key)
    val decrypt = String(decryptByte, Charsets.UTF_8)

    println("key: ${key.size * 8} bit! (256 bit required for 14 encrypted rounds)")
    println("encrypted API key -> $encrypt")
    println("decrypted API key -> $decrypt")
}



