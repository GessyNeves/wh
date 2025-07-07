/**
 * HKDF-SHA256 com salt zerado (esquema usado pelo WhatsApp)
 * Adaptado para usar CryptoJS
 */
function hkdf(mediaKey, info, length = 112) {
    const salt = CryptoJS.lib.WordArray.create(new Uint8Array(32)); // 32 bytes de zeros
    
    let mediaKeyWordArray;
    // Se mediaKey for uma string, assume que é Base64 e converte para WordArray
    if (typeof mediaKey === 'string') {
        mediaKeyWordArray = CryptoJS.enc.Base64.parse(mediaKey);
    } 
    // Se já for um WordArray (ou algo que se pareça com um), usa diretamente
    else if (mediaKey && typeof mediaKey.words !== 'undefined' && typeof mediaKey.sigBytes !== 'undefined') {
        mediaKeyWordArray = mediaKey;
    } 
    // Caso contrário, tenta criar um WordArray (pode ser um Buffer, etc.)
    else {
        mediaKeyWordArray = CryptoJS.lib.WordArray.create(mediaKey);
    }

    const prk = CryptoJS.HmacSHA256(mediaKeyWordArray, salt); 
    
    let okm = CryptoJS.lib.WordArray.create();
    let t = CryptoJS.lib.WordArray.create();
    
    const iterations = Math.ceil(length / 32);
    for (let i = 1; i <= iterations; i++) {
        const hmac = CryptoJS.HmacSHA256.create(prk); 
        hmac.update(t);
        hmac.update(CryptoJS.enc.Utf8.parse(info)); 
        hmac.update(CryptoJS.lib.WordArray.create([i])); 
        t = hmac.finalize();
        okm = okm.concat(t);
    }
    return okm.clamp(length);
}
