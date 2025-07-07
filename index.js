const express = require('express');
const bodyParser = require('body-parser');
const CryptoJS = require('crypto-js'); // Agora pode ser importado via require()

const app = express();
// A porta que o EasyPanel vai expor. process.env.PORT é a variável de ambiente que o EasyPanel usa.
const port = process.env.PORT || 3000; 

// Aumentar o limite do body para permitir o envio de mídias grandes em base64
app.use(bodyParser.json({ limit: '50mb' })); 

// Middleware para logar requisições (opcional, mas útil para depuração)
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

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
        // Isso pode acontecer se mediaKey for um Buffer ou Uint8Array direto
        // CryptoJS.lib.WordArray.create pode lidar com isso
        mediaKeyWordArray = CryptoJS.lib.WordArray.create(mediaKey);
    }

    // Para HKDF, o PRK é HMAC-SHA256(salt, IKM)
    // Onde IKM (Input Keying Material) é a mediaKey
    // E o salt é o salt (que no nosso caso é zero)
    // Então, a chave do HMAC é o salt, e a mensagem é a mediaKeyWordArray
    const prk = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, salt);
    prk.update(mediaKeyWordArray);
    const prkFinal = prk.finalize(); // Finaliza para obter o PRK

    let okm = CryptoJS.lib.WordArray.create();
    let t = CryptoJS.lib.WordArray.create();
    
    const iterations = Math.ceil(length / 32);
    for (let i = 1; i <= iterations; i++) {
        // Cria uma nova instância de HMAC para cada iteração
        // A chave é o PRK finalizado
        const hmac = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, prkFinal); 
        hmac.update(t);
        hmac.update(CryptoJS.enc.Utf8.parse(info)); 
        hmac.update(CryptoJS.lib.WordArray.create([i])); 
        t = hmac.finalize();
        okm = okm.concat(t);
    }
    return okm.clamp(length);
}

/**
 * Descriptografa mídia do WhatsApp a partir de string base64
 * Adaptado para usar CryptoJS
 */
function decryptWhatsAppMediaFromBase64(encBase64, mediaKeyB64, mediaType = "Audio") {
    try {
        // 1. Converte base64 para WordArray (CryptoJS)
        const encWordArray = CryptoJS.enc.Base64.parse(encBase64);
        
        // 2. Separa MAC e conteúdo criptografado
        // Para manipular os bytes diretamente, é mais fácil converter para Uint8Array
        const encBuffer = new Uint8Array(encWordArray.sigBytes);
        for (let i = 0; i < encWordArray.sigBytes; i++) {
            encBuffer[i] = (encWordArray.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xFF;
        }
        
        const macFile = CryptoJS.lib.WordArray.create(encBuffer.slice(encBuffer.length - 10));      
        const cipherText = CryptoJS.lib.WordArray.create(encBuffer.slice(0, encBuffer.length - 10)); 
        
        // 3. Deriva chaves usando HKDF
        const mediaKey = CryptoJS.enc.Base64.parse(mediaKeyB64); 
        const info = `WhatsApp ${mediaType} Keys`;
        const keys = hkdf(mediaKey, info, 112); 
        
        const iv = keys.clone().clamp(16);        
        const cipherKey = keys.clone().start(16).clamp(32); 
        const macKey = keys.clone().start(48).clamp(32);    
        
        // 4. Valida MAC
        const hmacToVerify = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, macKey); // Cria HMAC com a chave
        hmacToVerify.update(iv);
        hmacToVerify.update(cipherText);
        const macCalc = hmacToVerify.finalize().clamp(10); 
        
        let macsMatch = true;
        if (macCalc.sigBytes !== macFile.sigBytes) {
            macsMatch = false;
        } else {
            // Compara byte a byte para maior precisão
            const macCalcBytes = new Uint8Array(macCalc.sigBytes);
            for (let i = 0; i < macCalc.sigBytes; i++) {
                macCalcBytes[i] = (macCalc.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xFF;
            }
            const macFileBytes = new Uint8Array(macFile.sigBytes);
            for (let i = 0; i < macFile.sigBytes; i++) {
                macFileBytes[i] = (macFile.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xFF;
            }

            for (let i = 0; i < macCalc.sigBytes; i++) {
                if (macCalcBytes[i] !== macFileBytes[i]) {
                    macsMatch = false;
                    break;
                }
            }
        }

        if (!macsMatch) {
            throw new Error("MAC mismatch – chave ou arquivo incorreto");
        }
        
        // 5. Descriptografa usando AES-256-CBC
        const decrypted = CryptoJS.AES.decrypt(
            { ciphertext: cipherText }, 
            cipherKey, 
            { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
        );
        
        // CryptoJS.AES.decrypt já lida com o unpadding, então o resultado já é o buffer limpo
        // O resultado de decrypt é um WordArray, precisamos convertê-lo para Uint8Array para compatibilidade
        const decryptedBytes = new Uint8Array(decrypted.sigBytes);
        for (let i = 0; i < decrypted.sigBytes; i++) {
            decryptedBytes[i] = (decrypted.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xFF;
        }
        
        return decryptedBytes;
        
    } catch (error) {
        throw new Error(`Erro na descriptografia: ${error.message}`);
    }
}

// Endpoint para descriptografar áudio
app.post('/decrypt-audio', (req, res) => {
    const { encBase64, mediaKeyB64 } = req.body;

    if (!encBase64 || !mediaKeyB64) {
        return res.status(400).json({ success: false, error: "Missing encBase64 or mediaKeyB64 in request body." });
    }

    try {
        const audioBytes = decryptWhatsAppMediaFromBase64(encBase64, mediaKeyB64);
        const audioBase64 = Buffer.from(audioBytes).toString('base64');
        res.json({ success: true, audioBase64: audioBase64 });
    } catch (error) {
        console.error("Decryption error:", error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Endpoint de saúde para verificar se o serviço está online
app.get('/', (req, res) => {
    res.send('WhatsApp Audio Decryptor Service is running. Send POST requests to /decrypt-audio.');
});

// Inicia o servidor
app.listen(port, () => {
    console.log(`Decryptor service listening on port ${port}`);
});
