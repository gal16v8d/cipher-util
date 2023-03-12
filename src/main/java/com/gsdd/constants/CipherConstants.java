package com.gsdd.constants;

import lombok.experimental.UtilityClass;

@UtilityClass
public final class CipherConstants {

  public static final int BASE_BUILD = 16;
  public static final int BYTE_RATE = 8192;
  public static final String SECRET_KEY = System.getenv("CIPHER_SECRET_KEY");
}
