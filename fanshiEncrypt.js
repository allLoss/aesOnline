const crypto = require('crypto');
const { Buffer } = require('buffer');
const KEY_LENGTH = 32;
const IV_LENGTH = 16;
function fill(buffer) {
   let bufFill = Buffer.alloc(KEY_LENGTH);
   buffer.copy(bufFill, 0, 0, buffer.length >= KEY_LENGTH ? KEY_LENGTH : buffer.length);
   for (let fillIndex = buffer.length, start = 0; fillIndex < KEY_LENGTH; fillIndex++, start++) {
      bufFill[fillIndex] = bufFill[start] ^ bufFill[start + 1];
   }

   return bufFill;
}

//不可逆
function randomIV() {
   //let bufRandomIv = Buffer.alloc(KEY_LENGTH);
   return window.crypto.getRandomValues(Buffer.alloc(IV_LENGTH));

}

function aes(bufPlaintext, bufKey, bufIV) {

   const cipher = crypto.createCipheriv('aes-256-cbc', bufKey, bufIV);
   return Buffer.concat([cipher.update(bufPlaintext), cipher.final()]);
}

function deAes(bufCiphertext, bufKey, bufIV) {

   /* console.log('解密不带iv密文');
   console.log(bufCiphertext.toString('hex'));
   console.log('解密key');
   console.log(bufKey.toString('hex'));
   console.log('解密IV');
   console.log(bufIV.toString('hex'));
   console.log('------------------------------------------------------------'); */

   const decipher = crypto.createDecipheriv('aes-256-cbc', bufKey, bufIV);
   return Buffer.concat([decipher.update(bufCiphertext), decipher.final()]);
}

function insert(bufCiphertext, bufKey, bufIV) {
   let insetIndex = bufKey.readUIntBE(0, 2) % bufCiphertext.length;

   /* console.log('插入iv下标');
   console.log(insetIndex);
   console.log('插入iv前的密文');
   console.log(bufCiphertext.toString('hex'));
   console.log('IV');
   console.log(bufIV.toString('hex'));  */

   return Buffer.concat(
      insetIndex > 0 ?
         [bufCiphertext.subarray(0, insetIndex), bufIV, bufCiphertext.subarray(insetIndex, bufCiphertext.length)] :
         [bufIV, bufCiphertext]
   );
}

function deInsert(bufCiphertext, bufKey) {
   let insetIndex = bufKey.readUIntBE(0, 2) % (bufCiphertext.length - IV_LENGTH);

   /* console.log('插入iv下标');
   console.log(insetIndex);
   console.log('插入iv后的密文');
   console.log(bufCiphertext.toString('hex'));
   console.log('IV');
   console.log(bufCiphertext.subarray(insetIndex, insetIndex + IV_LENGTH).toString('hex'));
   console.log('去除iv后的密文');
   console.log(Buffer.concat([bufCiphertext.subarray(0, insetIndex), bufCiphertext.subarray(insetIndex + IV_LENGTH , bufCiphertext.length)]).toString('hex'));
   console.log('------------------------------------------------------------');
 */
   return [
      insetIndex > 0 ?
         Buffer.concat([bufCiphertext.subarray(0, insetIndex), bufCiphertext.subarray(insetIndex + IV_LENGTH, bufCiphertext.length)]) :
         bufCiphertext.subarray(IV_LENGTH, bufCiphertext.length)
      ,
      bufCiphertext.subarray(insetIndex, insetIndex + IV_LENGTH)
   ]
}
/*
加密过程：
 对密钥进行填充处理
 根据密钥生成随机iv
 进行aes-cbc-256加密
 将iv种子嵌入密文当中,位置由密钥决定
*/
function encrypt(plaintext, key, cipherCoding) {

   let bufPlaintext = Buffer.from(plaintext);
   let bufKey = Buffer.from(key);
   let bufFillKey = fill(bufKey);
   let bufIv = randomIV();

   return insert(
      aes(bufPlaintext, bufFillKey, bufIv),
      bufFillKey,
      bufIv,

   ).toString(cipherCoding);
}
function decrypt(Ciphertext, key, cipherCoding) {
   let bufCiphertext = Buffer.from(Ciphertext, cipherCoding);
   let bufKey = Buffer.from(key);
   let bufFillKey = fill(bufKey);
   let bufArray = deInsert(bufCiphertext, bufFillKey);

   return deAes(bufArray[0], bufFillKey, bufArray[1]).toString('utf8');

}

//页面操作
document.getElementById('buttonEncrypt').addEventListener('click', () => {
   //获取下拉框的值
   let codingSelect = document.getElementById('ciphertextCode');

   document.getElementById('ciphertext').value = encrypt(
      document.getElementById('plaintext').value, document.getElementById('pwd').value, codingSelect.options[codingSelect.options.selectedIndex].value
   );

}, false);
document.getElementById('buttonDecrypt').addEventListener('click', () => {
   //获取下拉框的值
   let codingSelect = document.getElementById('ciphertextCode');

   document.getElementById('plaintext').value = decrypt(
      document.getElementById('ciphertext').value, document.getElementById('pwd').value, codingSelect.options[codingSelect.options.selectedIndex].value
   );

}, false);










