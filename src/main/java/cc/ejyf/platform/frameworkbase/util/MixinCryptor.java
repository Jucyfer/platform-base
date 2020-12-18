package cc.ejyf.platform.frameworkbase.util;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.stream.Collectors;

@Component
public class MixinCryptor {
    Base64.Encoder encoder = Base64.getEncoder();
    Base64.Decoder decoder = Base64.getDecoder();
    SecureRandom rand = new SecureRandom();

    public String aesStr2StrEncrypt(String message, String aesKey) throws GeneralSecurityException {
        return aesStr2StrEncrypt(message, aesKey, null);
    }

    public String aesStr2StrEncrypt(String message, String aesKey, String provider) throws GeneralSecurityException {
        return encoder.encodeToString(
                specAESCrypto(
                        Cipher.ENCRYPT_MODE,
                        message.getBytes(StandardCharsets.UTF_8),
                        decoder.decode(aesKey),
                        provider
                )
        );
    }

    public String aesStr2StrDecrypt(String ciphertext, String aesKey) throws GeneralSecurityException {
        return aesStr2StrDecrypt(ciphertext, aesKey, null);
    }

    public String aesStr2StrDecrypt(String ciphertext, String aesKey, String provider) throws GeneralSecurityException {
        return new String(
                specAESCrypto(
                        Cipher.DECRYPT_MODE,
                        decoder.decode(ciphertext),
                        decoder.decode(aesKey),
                        provider
                ),
                StandardCharsets.UTF_8
        );
    }

    /**
     * AES加解密方法
     *
     * @param mode     {@linkplain Integer int}类型。{@link Cipher#ENCRYPT_MODE},{@link Cipher#DECRYPT_MODE}两种，分别代表加密模式和解密模式。含义同原生方法。
     * @param todo     {@linkplain Byte byte}[]类型。<br/>处于加密模式时，此参数应为待加密字节数组，例如{@link String#getBytes(Charset)}<br/>处于解密模式时，此参数应为待解密的字节数组，例如{@link Base64.Decoder#decode(String)}。
     * @param secret   {@linkplain Byte byte}[]类型。一般从{@link Base64.Decoder#decode(String)}解码而来。
     * @param provider {@link String}类型。当使用null时，使用java默认实现。可传递providerNameString来使用指定供应商（可能需要{@linkplain Security#addProvider(Provider) 额外的事先注册代码}）。
     * @return
     * @throws GeneralSecurityException
     */
    public byte[] specAESCrypto(int mode, byte[] todo, byte[] secret, String provider) throws GeneralSecurityException {
        var key = new SecretKeySpec(secret, "AES");
        return crypto(mode, todo, key, "AES", provider);
    }

    public String rsaStr2StrPubEncrypt(String message, String pubKey) throws GeneralSecurityException {
        return rsaStr2StrPubEncrypt(message, pubKey, null);
    }

    public String rsaStr2StrPubEncrypt(String message, String pubKey, String provider) throws GeneralSecurityException {
        return encoder.encodeToString(
                specRSACrypto(
                        Cipher.ENCRYPT_MODE,
                        message.getBytes(StandardCharsets.UTF_8),
                        decoder.decode(pubKey),
                        PUBKEY,
                        provider
                )
        );
    }

    public String rsaStr2StrPriEncrypt(String message, String priKey) throws GeneralSecurityException {
        return rsaStr2StrPriEncrypt(message, priKey, null);
    }

    public String rsaStr2StrPriEncrypt(String message, String priKey, String provider) throws GeneralSecurityException {
        return encoder.encodeToString(
                specRSACrypto(
                        Cipher.ENCRYPT_MODE,
                        message.getBytes(StandardCharsets.UTF_8),
                        decoder.decode(priKey),
                        PRIKEY,
                        provider
                )
        );
    }

    public String rsaStr2StrPubDecrypt(String ciphertext, String pubKey) throws GeneralSecurityException {
        return rsaStr2StrPubDecrypt(ciphertext, pubKey, null);
    }

    public String rsaStr2StrPubDecrypt(String ciphertext, String pubKey, String provider) throws GeneralSecurityException {
        return new String(
                specRSACrypto(
                        Cipher.DECRYPT_MODE,
                        decoder.decode(ciphertext),
                        decoder.decode(pubKey),
                        PUBKEY,
                        provider
                ),
                StandardCharsets.UTF_8
        );
    }

    public String rsaStr2StrPriDecrypt(String ciphertext, String priKey) throws GeneralSecurityException {
        return rsaStr2StrPriDecrypt(ciphertext, priKey, null);
    }

    public String rsaStr2StrPriDecrypt(String ciphertext, String priKey, String provider) throws GeneralSecurityException {
        return new String(
                specRSACrypto(
                        Cipher.DECRYPT_MODE,
                        decoder.decode(ciphertext),
                        decoder.decode(priKey),
                        PRIKEY,
                        provider
                ),
                StandardCharsets.UTF_8
        );
    }


    public static final int PUBKEY = 0;
    public static final int PRIKEY = 1;


    /**
     * RSA加解密方法
     *
     * @param mode     {@linkplain Integer int}类型。{@link Cipher#ENCRYPT_MODE},{@link Cipher#DECRYPT_MODE}两种，分别代表加密模式和解密模式。含义同原生方法。
     * @param todo     {@linkplain Byte byte}[]类型。<br/>处于加密模式时，此参数应为待加密字节数组，例如{@link String#getBytes(Charset)}<br/>处于解密模式时，此参数应为待解密的字节数组，例如{@link Base64.Decoder#decode(String)}。
     * @param secret   {@linkplain Byte byte}[]类型。一般从{@link Base64.Decoder#decode(String)}解码而来。
     * @param type     {@linkplain Integer int}类型。取值{@link MixinCryptor#PUBKEY}或{@link MixinCryptor#PRIKEY}。
     * @param provider @param provider {@link String}类型。当使用null时，使用java默认实现。可传递providerNameString来使用指定供应商（可能需要{@linkplain Security#addProvider(Provider) 额外的事先注册代码}）。
     * @return
     * @throws GeneralSecurityException
     */
    public byte[] specRSACrypto(int mode, byte[] todo, byte[] secret, int type, String provider) throws GeneralSecurityException {
        var keyFactory = provider == null ? KeyFactory.getInstance("RSA") : KeyFactory.getInstance("RSA", provider);
        return crypto(
                mode,
                todo,
                PUBKEY == type ?
                        keyFactory.generatePublic(new X509EncodedKeySpec(secret)) :
                        keyFactory.generatePrivate(new PKCS8EncodedKeySpec(secret)),
                "RSA",
                provider
        );
    }

    /**
     * wrapped vanilla crypt function
     *
     * @throws GeneralSecurityException
     */
    public byte[] crypto(int mode, byte[] todo, Key secret, String algorithm, String provider) throws GeneralSecurityException {
        var cipher = provider == null ? Cipher.getInstance(algorithm) : Cipher.getInstance(algorithm, provider);
        cipher.init(mode, secret);
        return cipher.doFinal(todo);
    }

    /**
     * 去除各种RSA先导格式，方便base64操作
     * @param formattedString
     * @return
     */
    public String reformatRSAKeyString(String formattedString){
        return Arrays.stream(formattedString.split("\n"))
                .dropWhile(s->s.contains("-----"))
                .takeWhile(s->!s.contains("-----"))
//                .filter(s->!s.contains("-----"))
                .collect(Collectors.joining());
    }

    public HashMap<String,String> generateRSA(int size)throws GeneralSecurityException{
        int realSize = Math.max(512,size);
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(realSize,rand);
        var pair = generator.generateKeyPair();
        HashMap<String,String> map = new HashMap<>(2);
        map.put("public", encoder.encodeToString(pair.getPublic().getEncoded()));
        map.put("private", encoder.encodeToString(pair.getPrivate().getEncoded()));
        return map;
    }
    public String generateAES(int size) throws GeneralSecurityException{
        int realSize = Math.min(256,size);
        var generator = KeyGenerator.getInstance("AES");
        generator.init(realSize,rand);
        return encoder.encodeToString(generator.generateKey().getEncoded());
    }
//
//    KeyPair rsaKeyPair;
//    String rsaPri, rsaPub;
//    SecretKey secretKey;
//    String aesKey;
//
//    private void init() throws Exception {
//        if (rsaKeyPair == null) {
//            var rsaKeyGenerator = KeyPairGenerator.getInstance("RSA");
//            rsaKeyGenerator.initialize(4096);
//            rsaKeyPair = rsaKeyGenerator.generateKeyPair();
//            rsaPub = encoder.encodeToString(rsaKeyPair.getPublic().getEncoded());
//            rsaPri = encoder.encodeToString(rsaKeyPair.getPrivate().getEncoded());
//        }
//        var generator = KeyGenerator.getInstance("AES");
//        generator.init(256);
//        secretKey = generator.generateKey();
//        aesKey = encoder.encodeToString(secretKey.getEncoded());
//    }
//
//    public static void main(String[] args) throws Exception {
//        var cryptor = new MixinCryptor();
//        var mapper = new ObjectMapper();
////        cryptor.init();
//        cryptor.aesKey="MGN5aEVSNnJybnVKTVV3V1kybVdUTTB0ZXVqTUJxYWc=";
//        cryptor.rsaPub = "-----BEGIN PUBLIC KEY-----\n" +
//                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqfpJo+3tSbwGOCLrAGst\n" +
//                "KtuoZwR/NoS74+ZgBIIbNoOtVEi8YeZuJg26vFw2iMNBuO0S+PoOEO9qRnkCoAkd\n" +
//                "GyxaSiZR1LvjSNl8nZYIlSknEa0R0tfWnfLWJyD2X48jZ9Uj2EBTnswSZ3cTFmlD\n" +
//                "c64MDQL7CCZXcaf2VuHq7cPJyMjnV1Z1MM+q5KcSPPvGH+HBPQO23BH2EOnx7pqS\n" +
//                "3rDdxNkelQ4bf/WZfubcEvJf2tLOQ16KWOT3J2GJGVC89biHo6b4ALUNU48zn8C+\n" +
//                "QinvKgJENQ5pMk7GJtJMQoM1V1d5XJEu3wmGwktTWu+MSd9KnQHmpXzwSDZ4h5Xm\n" +
//                "OwIDAQAB\n" +
//                "-----END PUBLIC KEY-----";
//
//        cryptor.rsaPri = "-----BEGIN PRIVATE KEY-----\n" +
//                "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCp+kmj7e1JvAY4\n" +
//                "IusAay0q26hnBH82hLvj5mAEghs2g61USLxh5m4mDbq8XDaIw0G47RL4+g4Q72pG\n" +
//                "eQKgCR0bLFpKJlHUu+NI2XydlgiVKScRrRHS19ad8tYnIPZfjyNn1SPYQFOezBJn\n" +
//                "dxMWaUNzrgwNAvsIJldxp/ZW4ertw8nIyOdXVnUwz6rkpxI8+8Yf4cE9A7bcEfYQ\n" +
//                "6fHumpLesN3E2R6VDht/9Zl+5twS8l/a0s5DXopY5PcnYYkZULz1uIejpvgAtQ1T\n" +
//                "jzOfwL5CKe8qAkQ1DmkyTsYm0kxCgzVXV3lckS7fCYbCS1Na74xJ30qdAealfPBI\n" +
//                "NniHleY7AgMBAAECggEBAIkfLSr+dI8oDIhauuOyklRhsT+x5AISIBTgsxLP9q4K\n" +
//                "mdhFeRstLiyqpLrxVNkNU0agkc6iwpgs27oQQurhj0ZtiEULFrab/+Wz9ZCXCUNz\n" +
//                "WF4tFRTXI/51eQdF0xsRuMk5q1n3wr12+V3YNGC++Dgo7vXMMsDHVYGNsu8x/zhg\n" +
//                "iFKlKoxfnsHe+8lyZCD6FHqbHMsPM+HonecCRfbNrV4NTUkhMGQIL0/EU/V4k2YW\n" +
//                "BMbz7o/P4RnXtSQfxnFRT0LHB6e15Hl2C9F4yKY5dN3BtffvsQZn6CMh5KB7dvnl\n" +
//                "jBJP88ZkchvcXmPccd2eNPXp1fpeCg7IbFIzt2BSHXECgYEA54EQPH2X9ykpsLHt\n" +
//                "zSA6hNnXNUDdXU20IFZk922UuMyBiLrzxPJTzIAMScb3mSUNKwLYheTQQpzw2wJH\n" +
//                "QqZrwDPLXM/5fwFc/KdY8GLrQRIQifCFeC37LjnWMpFHd3bbbxxtIFMuJ5kjR+20\n" +
//                "Ub1hqtvdqyw4dBArl930J5+4ZBkCgYEAu/abpvlmvLz/gXE9bJaxpYC/3n/T00Ij\n" +
//                "jjsqPw8S+Sd2gqAfHBX/U7iS2KkXP6ShqLO8S7YxHNk66/YhGFTnQqYXoYOk0GCW\n" +
//                "JmCpZhxd5GNDc2xoxR9LwUvzG8NeN91DhcCuDYbCRquABD+38uZbDzE+O4z8z6aA\n" +
//                "D98nQ9OuR3MCgYAT4zR/3dI2O2UHduGU45XjX8trGb1qjIhS1tkpoFJMZdUi59yV\n" +
//                "KLQmN0HW/K68i0BMV5w+NF/nuQ+/4Lw6b42GH2zy9jLaxEU2tzGexQCswF6HWxA8\n" +
//                "OMcBO5q5EV3wV1eWffyp8Dtgz3kGbtc0xm4jfWvXjp7y6Yi1LS4SUVhH0QKBgGhf\n" +
//                "BIlQPasZ62rOHYR5nQVAm8oKAu5w8FtfIRNI5IkzT4wzK3MmB9ROTkQ+iGlPmnCZ\n" +
//                "9Tm5XkYdnak+z5u6MXwBzGdkORV4PIfs7sODhuN19xNVpEupGCCqcsD82Al/NKpF\n" +
//                "lqBuLtydCIXTd+pJ3VBvUJYysIMBemTVzfDMzx5fAoGBAJVFh1kn+j2o1ti6PpGZ\n" +
//                "laOoT8MY49olnJDvlb4weqwXh3Y/Jqor0JrTsFM9Pj42/j8BrCbHFtLfitz/fnH7\n" +
//                "qIszr8ZRm7edU4Ipwj4+tBelO2zZFy9wuRk9N+zqSrpdOpArNBoCwaZtc8TXgJWL\n" +
//                "nlmJoAobmuMfWu5OPW51HZLf\n" +
//                "-----END PRIVATE KEY-----";
//        cryptor.rsaPub = cryptor.fuckoffformat(cryptor.rsaPub);
//        cryptor.rsaPri = cryptor.fuckoffformat(cryptor.rsaPri);
//        System.out.println("AES密钥：" + cryptor.aesKey);
//        System.out.println("RSA公钥：" + cryptor.rsaPub);
//        System.out.println("RSA私钥：" + cryptor.rsaPri);
//        //加密：
//        //首先加密报文：
////        var data = "测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC测试文字ABC";
//        var data = mapper.writeValueAsString(
//                Map.of(
//                        "code", "000000",
//                        "msg", "success",
//                        "payload", Map.of(
//                                "name", "jyf",
//                                "message", "hello"
//                        )
//                )
//        );
////        data="{\"msg\":\"success\",\"code\":\"000000\",\"payload\":{\"name\":\"jyf\",\"message\":\"hello\"}}";
//        System.out.println("待处理的报文明文：" + data);
//        //用AES密钥加密报文：
////        var encrypted_data = cryptor.aesStr2StrEncrypt(data,cryptor.aesKey);
//        var encrypted_data = cryptor.aesStr2StrEncrypt(data, "eHhlenRjTTdYNU85Q2hqb3ppamtQbjZzWEZqV2dPVDg=");
//        System.out.println("AES加密的密文：" + encrypted_data);
//        //再用PUB_KEY加密AES密钥
//        var encrypted_aes = cryptor.rsaStr2StrPubEncrypt(cryptor.aesKey, cryptor.rsaPub);
//        System.out.println("RSA_PUB加密的AES密钥：" + encrypted_aes);
//        var resp = Map.of("b", encrypted_aes, "l", encrypted_data);
//        System.out.println("处理后的加密报文：" + mapper.writeValueAsString(resp));
//        System.out.println("->>>>>>>>>>>>>>>>>>>S端报文发送->>>>>>>>>>>>>>>>>>>>\n.\n.\n.\n<<<<<<<<<<<<<<<<<<<-R端报文接收<<<<<<<<<<<<<<<<<<<<-");
//        //用私钥解密AES密钥
//        var decrypted_aes = cryptor.rsaStr2StrPriDecrypt(encrypted_aes, cryptor.rsaPri);
//        System.out.println("RSA_PRI解密的AES密钥：" + decrypted_aes);
//        //用解密之后的AES密钥解密密文：
////        var decrypted_data = cryptor.aesStr2StrDecrypt(encrypted_data,decrypted_aes);
//        var decrypted_data = cryptor.aesStr2StrDecrypt(encrypted_data, "eHhlenRjTTdYNU85Q2hqb3ppamtQbjZzWEZqV2dPVDg=");
//        System.out.println("解密后的AES密钥解密的密文：" + decrypted_data);
//    }
}
