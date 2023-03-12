package com.gsdd.cipher;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public enum CipherAlgorithm {
  AES("AES", "AES", 16),
  AES_WITH_PADDING("AES/ECB/PKCS5Padding", "AES", 16),
  DESEDE("DESede", "DESede", 24),
  PBEWITHSHA1ANDDESEDE("PBEWITHSHA1ANDDESEDE", "PBEWITHSHA1ANDDESEDE", 24);

  private final String algorithm;
  private final String keyAlgorithm;
  private final int baseByte;
}
