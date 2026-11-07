async function aesGcmDecrypt(keyBytes, cipherBase64) {
    const key = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
    );

    const buf = Uint8Array.from(atob(cipherBase64), c => c.charCodeAt(0));

    const nonce = buf.slice(0, 16); // 前 16 字节 = nonce
    const tag = buf.slice(16, 32); // 接下来 16 字节 = tag
    const ct = buf.slice(32); // 剩余 = 密文

    const data = new Uint8Array(ct.length + tag.length);
    data.set(ct, 0);
    data.set(tag, ct.length);

    const plainBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce },
        key,
        data
    );
    return new TextDecoder().decode(plainBuf);
}

document.getElementById("aes-btn").addEventListener("click", async function() {
    if (!window.crypto || !window.crypto.subtle) {
        document.getElementById("result").textContent = "当前环境不支持Web Crypto API";
        return;
    }
    const aesKey = new TextEncoder().encode(document.getElementById("aes-key").value);
    if (aesKey.length !== 32) {
        document.getElementById("result").textContent = "输入长度必须为32个字节";
        return;
    }

    try {
        const plaintext = await aesGcmDecrypt(aesKey, "rAQaA5a5obbw+3RQF2dOwNk2TjtCVM6KOuOsp+ZgW9s0UOylLZeddT3+H2daiL/8DPRup5dBOYQHErRxqQ3GPJvF56ce5s8=");
        document.getElementById("result").textContent = plaintext;
    } catch (e) {
        console.error(e);
        document.getElementById("result").textContent = "解密失败，再试试吧";
    }
});