package com.gsdd.cipher;

import com.gsdd.constants.CipherConstants;
import com.gsdd.constants.NumericConstants;
import com.gsdd.exception.TechnicalException;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.experimental.UtilityClass;

@UtilityClass
public final class CipherUtil {

  private static final int HEX_100 = 0x100;
  private static final int HEX_FF = 0xff;

  public static String generateFileId(String file, String algorithm, String salt, Integer buffer) {
    try (FileInputStream fis = new FileInputStream(file)) {
      int r = buffer != null ? buffer : CipherConstants.BYTE_RATE;
      byte[] dataBytes = new byte[r];
      int nread = NumericConstants.ZERO;
      MessageDigest md = MessageDigest.getInstance(algorithm);
      if (salt != null) {
        md.update(salt.getBytes());
      }
      while ((nread = fis.read(dataBytes)) != NumericConstants.MINUS_ONE) {
        md.update(dataBytes, NumericConstants.ZERO, nread);
      }
      byte[] mdbytes = md.digest();
      StringBuilder sb = new StringBuilder();
      int max = mdbytes.length;
      for (int i = 0; i < max; i++) {
        sb.append(
            Integer.toString((mdbytes[i] & HEX_FF) + HEX_100, CipherConstants.BASE_BUILD)
                .substring(NumericConstants.ONE));
      }
      return sb.toString();
    } catch (Exception e) {
      throw new TechnicalException(e);
    }
  }

  public static String encode(String source, String salt, DigestAlgorithm digestAlgorithm,
      CipherAlgorithm cypherAlgorithm) {
    return encode(source, salt, digestAlgorithm, cypherAlgorithm, 1);
  }

  public static String encode(String source, String salt, DigestAlgorithm digestAlgorithm,
      CipherAlgorithm cipherAlgorithm, int encodeTimes) {
    try {
      byte[] buf = executeCipher(
          source.getBytes(StandardCharsets.UTF_8),
          salt,
          digestAlgorithm,
          cipherAlgorithm,
          encodeTimes,
          Cipher.ENCRYPT_MODE);
      return Base64.getEncoder().encodeToString(buf);
    } catch (Exception e) {
      throw new TechnicalException(e);
    }
  }

  public static String decode(String source, String salt, DigestAlgorithm digestAlgorithm,
      CipherAlgorithm cypherAlgorithm) {
    return decode(source, salt, digestAlgorithm, cypherAlgorithm, 1);
  }

  public static String decode(String source, String salt, DigestAlgorithm digestAlgorithm,
      CipherAlgorithm cipherAlgorithm, int decodeTimes) {
    try {
      byte[] buf = executeCipher(
          Base64.getDecoder().decode(source.getBytes(StandardCharsets.UTF_8)),
          salt,
          digestAlgorithm,
          cipherAlgorithm,
          decodeTimes,
          Cipher.DECRYPT_MODE);
      return new String(buf, StandardCharsets.UTF_8);
    } catch (Exception e) {
      throw new TechnicalException(e);
    }
  }

  private static SecretKey getKey(String salt, DigestAlgorithm digestAlgorithm,
      CipherAlgorithm cypherAlgorithm) throws NoSuchAlgorithmException {
    String cypherKey = salt == null ? CipherConstants.SECRET_KEY : salt;
    MessageDigest digester = MessageDigest.getInstance(digestAlgorithm.getAlgorithm());
    byte[] cypherKeyBytes = digester.digest(cypherKey.getBytes(StandardCharsets.UTF_8));
    cypherKeyBytes = Arrays.copyOf(cypherKeyBytes, cypherAlgorithm.getBaseByte());
    return new SecretKeySpec(cypherKeyBytes, cypherAlgorithm.getKeyAlgorithm());
  }

  private static byte[] executeCipher(byte[] sourceBuffer, String salt, DigestAlgorithm digestAlgorithm,
      CipherAlgorithm cypherAlgorithm, int cipherTimes, int cipherMode) throws Exception {
    SecretKey key = getKey(salt, digestAlgorithm, cypherAlgorithm);
    Cipher cipher = Cipher.getInstance(cypherAlgorithm.getAlgorithm());
    cipher.init(cipherMode, key);
    byte[] buf = sourceBuffer;
    while (cipherTimes > 0) {
      buf = cipher.doFinal(buf);
      cipherTimes--;
    }
    return buf;
  }
}
