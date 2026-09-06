/*
 * Copyright (c) 2026 John Eric Sobrepena
 * SPDX-License-Identifier: MIT
 */
package io.github.johnsobrepena.ideasparx.examples;

import java.security.SecureRandom;
import java.util.LinkedHashSet;
import java.util.Set;

public final class Util {
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private Util() {
    throw new AssertionError("Utility class");
  }

  public static byte[] generateID(int length) {
    var secureBytes = new byte[length];
    SECURE_RANDOM.nextBytes(secureBytes);
    return secureBytes;
  }

  public static Set<byte[]> getRandomIDs(int length) {
    Set<byte[]> members = new LinkedHashSet<>();
    for (int i = 0; i < length; i++) {
      members.add(generateID(32));
    }

    return members;
  }
}
