package com.gsdd.cipher;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public enum CipherAlgorithm {
  AES("AES", "AES", 16),
  AES_WITH_PADDING("AES/ECB/PKCS5Padding", "AES", 16),
  DES_EDE("DESede", "DESede", 24),
  PBE_WITH_SHA1_AND_DES_EDE("PBEWITHSHA1ANDDESEDE", "PBEWITHSHA1ANDDESEDE", 24);

  private final String algorithm;
  private final String keyAlgorithm;
  private final int baseByte;
}
