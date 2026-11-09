"use strict";

const result = document.getElementById("result");
const keyInput = document.getElementById("key-input");
const aesBtn = document.getElementById("aes-btn");
let timer;
const KEY = "key-input";

result.textContent = "点击“提交”以校验输入框内容是否正确";
keyInput.value = sessionStorage.getItem(KEY) ?? "";

async function aesGcmEncrypt(keyBytes, plaintext) {
    const key = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']
    );

    const nonce = crypto.getRandomValues(new Uint8Array(16)); // 随机 16 字节 nonce
    const data = new TextEncoder().encode(plaintext);

    const encBuf = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce },
        key,
        data
    );

    const enc = new Uint8Array(encBuf);
    const ct = enc.slice(0, enc.length - 16); // 前段 = 密文
    const tag = enc.slice(enc.length - 16);   // 后 16 字节 = tag

    const out = new Uint8Array(nonce.length + tag.length + ct.length);
    out.set(nonce, 0);                     // [0,16)  = nonce
    out.set(tag, nonce.length);            // [16,32) = tag
    out.set(ct, nonce.length + tag.length);// [32,)   = 密文

    return btoa(String.fromCharCode(...out));
}

async function aesGcmDecrypt(keyBytes, cipherBase64) {
    const key = await crypto.subtle.importKey(
        "raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]
    );

    const buf = Uint8Array.from(atob(cipherBase64), c => c.charCodeAt(0));

    const nonce = buf.slice(0, 16); // 前 16 字节 = nonce
    const tag = buf.slice(16, 32); // 接下来 16 字节 = tag
    const ct = buf.slice(32); // 剩余 = 密文

    const data = new Uint8Array(ct.length + tag.length);
    data.set(ct, 0);
    data.set(tag, ct.length);

    const plainBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce },
        key,
        data
    );
    return new TextDecoder().decode(plainBuf);
}

keyInput.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
        sessionStorage.setItem(KEY, keyInput.value);
    }, 300);
});

aesBtn.addEventListener("click", async () => {
    if (!window.crypto || !window.crypto.subtle) {
        result.textContent = "当前环境不支持Web Crypto API";
        return;
    }
    const aesKey = new TextEncoder().encode(keyInput.value);
    if (aesKey.length !== 32) {
        result.textContent = "输入长度必须为32个字节";
        return;
    }

    try {
        const plaintext = await aesGcmDecrypt(aesKey, "hheDgSyqCv7p6Qv2wLgv/k7eyCekgb1tUEH1MmCB4AHbh+aeFd/yGAEPqL27Wt82TGhS3wlKc1gvKUW5o1rhftBUKghPU08=");
        result.textContent = plaintext;
    } catch (e) {
        console.error(e);
        result.textContent = "解密失败，再试试吧";
    }
});