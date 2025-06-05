package com.gsdd.cipher;

import com.gsdd.exception.TechnicalException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class CipherUtilTest {

  private static final String KEY = "Kmgr$%2018";
  private static final String SALT = "randomize";
  private static final String CIPHER_WITHOUT_SALT = "ilT8fYZwZ6ExPD/hfFk67g==";
  private static final String CIPHER_WITH_SALT = "aOsh+XUBkQ1Z9zXItgVEEQ==";
  private static final String ENC_FILE_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
  private static final String ENC_FILE_SHA1_SALT = "5458fb3b7d49ab5285ad3f4022ba3fdaf6d0894d";
  private static final String TEST_TXT = "test1.txt";

  @ParameterizedTest(name = "using salt={0} digestAlgorithm={1} cypherAlgorithm={2}")
  @CsvSource({",,", "lol,,", "lol,MD5,", "lol,,AES", ",MD5,AES"})
  void testDecodeBadAlgorithm(String salt, String digestAlgorithm, String cypherAlgorithm) {
    DigestAlgorithm digest =
        Optional.ofNullable(digestAlgorithm).map(DigestAlgorithm::valueOf).orElse(null);
    CipherAlgorithm cypher =
        Optional.ofNullable(cypherAlgorithm).map(CipherAlgorithm::valueOf).orElse(null);
    Assertions.assertThrows(
        TechnicalException.class,
        () -> CipherUtil.decode(CIPHER_WITHOUT_SALT, salt, digest, cypher));
  }

  @ParameterizedTest(
      name = "using digestAlgorithm={0} cypherAlgorithm={1} decodeTimes={2} value= {3}")
  @CsvSource({
    "SHA512,DES_EDE,1,ilT8fYZwZ6ExPD/hfFk67g==",
    "SHA1,AES,1,HycezNqAuI4rr4UFSF/wMA==",
    "MD5,AES_WITH_PADDING,1,lhV7Tg+nBXsFVurBa9xEUA==",
    "SHA512,DES_EDE,2,ltY4ilgI23M+tXSQDFyLS/QC12H/ELUo",
    "SHA1,AES,2,cufEH5sAaygU6LC7MUxTjX2BPy31JzLjO5Uc08nwg6c=",
    "MD5,AES_WITH_PADDING,2,grCe/T72uZ7BCI98qhEVGY7K2LJ21V86cvnlmMCdnWM="
  })
  void testDecodeWithoutSalt(
      String digestAlgorithm, String cypherAlgorithm, int decodeTimes, String value) {
    DigestAlgorithm digest =
        Optional.ofNullable(digestAlgorithm).map(DigestAlgorithm::valueOf).orElse(null);
    CipherAlgorithm cypher =
        Optional.ofNullable(cypherAlgorithm).map(CipherAlgorithm::valueOf).orElse(null);
    Assertions.assertEquals(KEY, CipherUtil.decode(value, null, digest, cypher, decodeTimes));
  }

  @Test
  void testDecodeWithSalt() {
    Assertions.assertEquals(
        KEY,
        CipherUtil.decode(CIPHER_WITH_SALT, SALT, DigestAlgorithm.SHA512, CipherAlgorithm.DES_EDE));
  }

  @ParameterizedTest(name = "using salt={0} digestAlgorithm={1} cypherAlgorithm={2}")
  @CsvSource({",,", "lol,,", "lol,MD5,", "lol,,AES"})
  void testCipherBadAlgorithm(String salt, String digestAlgorithm, String cypherAlgorithm) {
    DigestAlgorithm digest =
        Optional.ofNullable(digestAlgorithm).map(DigestAlgorithm::valueOf).orElse(null);
    CipherAlgorithm cypher =
        Optional.ofNullable(cypherAlgorithm).map(CipherAlgorithm::valueOf).orElse(null);
    Assertions.assertThrows(
        TechnicalException.class, () -> CipherUtil.encode(KEY, salt, digest, cypher));
  }

  @ParameterizedTest(
      name = "using digestAlgorithm={0} cypherAlgorithm={1} encodeTime={2} value= {3}")
  @CsvSource({
    "SHA512,DES_EDE,1,ilT8fYZwZ6ExPD/hfFk67g==",
    "SHA1,AES,1,HycezNqAuI4rr4UFSF/wMA==",
    "MD5,AES_WITH_PADDING,1,lhV7Tg+nBXsFVurBa9xEUA==",
    "SHA512,DES_EDE,2,ltY4ilgI23M+tXSQDFyLS/QC12H/ELUo",
    "SHA1,AES,2,cufEH5sAaygU6LC7MUxTjX2BPy31JzLjO5Uc08nwg6c=",
    "MD5,AES_WITH_PADDING,2,grCe/T72uZ7BCI98qhEVGY7K2LJ21V86cvnlmMCdnWM="
  })
  void testCipherWithoutSalt(
      String algorithmDigest, String algorithmCypher, int encodeTime, String value) {
    DigestAlgorithm digest =
        Optional.ofNullable(algorithmDigest).map(DigestAlgorithm::valueOf).orElse(null);
    CipherAlgorithm cypher =
        Optional.ofNullable(algorithmCypher).map(CipherAlgorithm::valueOf).orElse(null);
    Assertions.assertEquals(value, CipherUtil.encode(KEY, null, digest, cypher, encodeTime));
  }

  @Test
  void testCipherWithSalt() {
    Assertions.assertEquals(
        CIPHER_WITH_SALT,
        CipherUtil.encode(KEY, SALT, DigestAlgorithm.SHA512, CipherAlgorithm.DES_EDE));
  }

  @Test
  void testGenerateFileIdThrowExc() {
    Assertions.assertThrows(
        TechnicalException.class, () -> CipherUtil.generateFileId("/log4j2.xml", null, null, 1024));
  }

  @Test
  void testGenerateFileIdNoBuffer(@TempDir Path tmpPath) throws IOException {
    Path file = Files.createFile(tmpPath.resolve(TEST_TXT));
    Assertions.assertEquals(
        ENC_FILE_SHA1,
        CipherUtil.generateFileId(
            file.toFile().getAbsolutePath(), DigestAlgorithm.SHA1.getAlgorithm(), null, null));
  }

  @Test
  void testGenerateFileIdWithBuffer(@TempDir Path tmpPath) throws IOException {
    Path file = Files.createFile(tmpPath.resolve(TEST_TXT));
    Assertions.assertEquals(
        ENC_FILE_SHA1_SALT,
        CipherUtil.generateFileId(
            file.toFile().getAbsolutePath(), DigestAlgorithm.SHA1.getAlgorithm(), KEY, 1024));
  }
}
