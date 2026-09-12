/*
 * Copyright (c) 2026 John Eric Sobrepena
 * SPDX-License-Identifier: MIT
 */
package io.github.johnsobrepena.ideasparx;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

/**
 * Merkle Tree with salted leaves and depth padding. Thread-safe for concurrent read access.
 * Designed for zero-copy performance; callers must treat input arrays and returned proof byte
 * arrays as read-only.
 */
public final class MerkleTree {

  private static final byte LEAF_PREFIX = (byte) 0x00;
  private static final byte INTERNAL_PREFIX = (byte) 0x01;
  private static final int SEED_NUM_BYTES = 32;
  private static final int PADDING_ELEM_NUM_BYTES = 32;

  /** Default target proof depth applied when constructing a tree with default parameters. */
  public static final int DEFAULT_MIN_PROOF_DEPTH = 10;

  /** Maximum allowed proof depth supported by tree construction and verification. */
  public static final int ALLOWED_MAX_PROOF_DEPTH = 13;

  /** Maximum allowed number of leaves permitted in a tree (1 << ALLOWED_MAX_PROOF_DEPTH). */
  public static final int ALLOWED_MAX_LEAF_COUNT = 1 << ALLOWED_MAX_PROOF_DEPTH;

  private final int targetProofDepth;
  private final boolean useSecureSeed;

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  /**
   * Leaf entry containing salt seed and payload.
   *
   * @param seed 32-byte salt array, or empty array if secure seed disabled.
   * @param data Raw leaf payload bytes.
   */
  public record Leaf(byte[] seed, byte[] data) {}

  /**
   * Proof entry containing Leaf and sibling proof hashes.
   *
   * @param leaf Associated Leaf instance.
   * @param siblingHashes List of 32-byte sibling hashes along audit path.
   */
  public record Proof(Leaf leaf, List<byte[]> siblingHashes) {}

  private final List<Leaf> seededLeaves;
  private final Map<ByteBuffer, Integer> leafIndexMap;
  private final List<List<byte[]>> layers;
  private final byte[] rootHash;
  private final List<byte[]> proofPaddings;

  /**
   * Construct tree with default target proof depth (10) and secure seeds.
   *
   * @param leaves Set of unique leaf payload byte arrays.
   * @throws IllegalArgumentException If leaves is null, empty, contains null or empty elements,
   *     exceeds ALLOWED_MAX_LEAF_COUNT, or has duplicate content.
   */
  public MerkleTree(Set<byte[]> leaves) {
    this(leaves, DEFAULT_MIN_PROOF_DEPTH, true);
  }

  /**
   * Construct tree with custom target depth and seed option.
   *
   * @param leaves Set of unique leaf payload byte arrays.
   * @param targetProofDepth Target minimum depth for proof padding (0 for no padding, up to
   *     ALLOWED_MAX_PROOF_DEPTH).
   * @param useSecureSeed Enable random 32-byte salt seeds per leaf if true.
   * @throws IllegalArgumentException If leaves is null, empty, contains null or empty elements,
   *     exceeds ALLOWED_MAX_LEAF_COUNT, has duplicate content, or targetProofDepth is negative or
   *     exceeds ALLOWED_MAX_PROOF_DEPTH.
   */
  public MerkleTree(Set<byte[]> leaves, int targetProofDepth, boolean useSecureSeed) {
    if (leaves == null || leaves.isEmpty()) {
      throw new IllegalArgumentException("Leaves must not be null or empty");
    }
    if (leaves.size() > ALLOWED_MAX_LEAF_COUNT) {
      throw new IllegalArgumentException(
          "Leaves count cannot exceed allowed maximum of " + ALLOWED_MAX_LEAF_COUNT);
    }
    if (targetProofDepth < 0 || targetProofDepth > ALLOWED_MAX_PROOF_DEPTH) {
      throw new IllegalArgumentException(
          "Target proof depth must be between 0 and " + ALLOWED_MAX_PROOF_DEPTH);
    }
    this.proofPaddings = new ArrayList<>();
    this.targetProofDepth = targetProofDepth;
    this.useSecureSeed = useSecureSeed;
    this.layers = new ArrayList<>();

    Map<ByteBuffer, Integer> indexMap = new HashMap<>();
    List<Leaf> leafList = new ArrayList<>(leaves.size());

    int index = 0;
    for (var leafData : leaves) {
      requireNonNullAndNonEmptyBytes(leafData, "leaf data must not be null nor empty");
      if (indexMap.putIfAbsent(ByteBuffer.wrap(leafData), index++) != null) {
        throw new IllegalArgumentException(
            "Duplicate leaf content detected. Leaves must be unique.");
      }
      leafList.add(new Leaf(generateSeedBytes(), leafData));
    }

    this.seededLeaves = Collections.unmodifiableList(leafList);
    this.leafIndexMap = Collections.unmodifiableMap(indexMap);

    initializeTree();
    initializeProofPaddings();

    this.rootHash = calculateRootHash();
  }

  private void initializeTree() {
    var nodes =
        this.seededLeaves.stream().map(leaf -> computeLeafHash(leaf.seed, leaf.data)).toList();

    layers.add(nodes);

    while (nodes.size() > 1) {
      List<byte[]> layer = new ArrayList<>();
      for (int i = 0; i < nodes.size(); i += 2) {
        var hash = computePairHashAtIndex(i, nodes);
        layer.add(hash);
      }
      nodes = layer;
      layers.add(layer);
    }
  }

  private void initializeProofPaddings() {
    for (int i = this.layers.size(); i < this.targetProofDepth; i++) {
      this.proofPaddings.add(generateSecureBytes(PADDING_ELEM_NUM_BYTES));
    }
  }

  private byte[] calculateRootHash() {
    var hash = layers.get(layers.size() - 1).get(0);
    for (var padding : this.proofPaddings) {
      hash = computePairHash(hash, padding);
    }
    return hash;
  }

  /**
   * Get root hash clone.
   *
   * @return Cloned 32-byte root hash array.
   */
  public byte[] getRoot() {
    return rootHash.clone();
  }

  /**
   * Get proofs for all leaves in tree.
   *
   * @return Unmodifiable list of Proof instances.
   */
  public List<Proof> getProofs() {
    return this.seededLeaves.stream()
        .map(leaf -> new Proof(leaf, getSiblingHashes(leaf.data())))
        .toList();
  }

  /**
   * Get map of leaf payload ByteBuffer to Proof instances for fast bulk lookup.
   *
   * @return Unmodifiable map mapping leaf payload ByteBuffer to Proof records.
   */
  public Map<ByteBuffer, Proof> getProofsAsMap() {
    Map<ByteBuffer, Proof> proofs = new HashMap<>(this.seededLeaves.size());
    for (var leaf : this.seededLeaves) {
      proofs.put(ByteBuffer.wrap(leaf.data()), new Proof(leaf, getSiblingHashes(leaf.data())));
    }
    return Collections.unmodifiableMap(proofs);
  }

  /**
   * Get proof record (Leaf + sibling hashes) for specific leaf payload. O(1) lookup.
   *
   * @param leafData Raw leaf payload bytes to search.
   * @return Proof instance containing Leaf and list of sibling hashes.
   * @throws IllegalArgumentException If leafData is null or empty.
   * @throws NoSuchElementException If leafData not found in tree.
   */
  public Proof getProof(byte[] leafData) {
    requireNonNullAndNonEmptyBytes(leafData, "leafData must not be null nor empty");
    List<byte[]> siblingHashes = getSiblingHashes(leafData);
    Integer leafIndex = leafIndexMap.get(ByteBuffer.wrap(leafData));
    Leaf leaf = seededLeaves.get(leafIndex);
    return new Proof(leaf, siblingHashes);
  }

  /**
   * Get sibling hashes audit path for specific leaf payload. O(1) lookup.
   *
   * @param leafData Raw leaf payload bytes to search.
   * @return Unmodifiable list of 32-byte sibling hashes.
   * @throws IllegalArgumentException If leafData is null or empty.
   * @throws NoSuchElementException If leafData not found in tree.
   */
  public List<byte[]> getSiblingHashes(byte[] leafData) {
    requireNonNullAndNonEmptyBytes(leafData, "leafData must not be null nor empty");
    Integer leafIndex = leafIndexMap.get(ByteBuffer.wrap(leafData));
    if (leafIndex == null) {
      throw new NoSuchElementException("Leaf data not found in Merkle Tree");
    }

    List<byte[]> proof = new ArrayList<>();
    int index = leafIndex;

    for (var layer : layers) {
      if (layer.size() <= 1) {
        continue;
      }
      byte[] siblingHash;
      if (index % 2 == 0) {
        siblingHash = layer.get(Math.min(index + 1, layer.size() - 1));
      } else {
        siblingHash = layer.get(index - 1);
      }
      index = index / 2;
      proof.add(siblingHash.clone());
    }

    proof.addAll(proofPaddings);

    return Collections.unmodifiableList(proof);
  }

  private byte[] computePairHashAtIndex(int index, List<byte[]> nodes) {
    var e1 = nodes.get(index);
    var e2 = index + 1 >= nodes.size() ? e1 : nodes.get(index + 1);
    return computePairHash(e1, e2);
  }

  private static byte[] computePairHash(byte[] input1, byte[] input2) {
    byte[] left, right;
    if (Arrays.compare(input1, input2) > 0) {
      left = input2;
      right = input1;
    } else {
      left = input1;
      right = input2;
    }

    MessageDigest md = newDigest();
    md.update(INTERNAL_PREFIX);
    md.update(left);
    md.update(right);
    return md.digest();
  }

  private static byte[] computeLeafHash(byte[] seed, byte[] leafData) {
    var md = newDigest();
    var buffer =
        ByteBuffer.allocate(Byte.BYTES + (2 * Integer.BYTES) + seed.length + leafData.length);
    buffer.put(LEAF_PREFIX).putInt(seed.length).put(seed).putInt(leafData.length).put(leafData);
    return md.digest(buffer.array());
  }

  private static MessageDigest newDigest() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  private byte[] generateSecureBytes(int numBytes) {
    var secureBytes = new byte[numBytes];
    SECURE_RANDOM.nextBytes(secureBytes);
    return secureBytes;
  }

  private byte[] generateSeedBytes() {
    if (!useSecureSeed) {
      return new byte[] {};
    }
    return generateSecureBytes(SEED_NUM_BYTES);
  }

  /**
   * Verify proof path against root hash.
   *
   * @param leafData Raw leaf payload bytes.
   * @param seedData Salt seed bytes.
   * @param rootHash Expected 32-byte root hash.
   * @param proof List of 32-byte sibling hashes.
   * @return True if proof path reconstructs rootHash; false if valid proof path does not match
   *     rootHash.
   * @throws NullPointerException If seedData or proof is null.
   * @throws IllegalArgumentException If leafData or rootHash is null/empty, proof depth exceeds
   *     ALLOWED_MAX_PROOF_DEPTH, or any proof element is null or not 32 bytes.
   */
  public static boolean verifyProof(
      byte[] leafData, byte[] seedData, byte[] rootHash, List<byte[]> proof) {
    requireNonNullAndNonEmptyBytes(leafData, "leafData must not be null nor empty");
    requireNonNullAndNonEmptyBytes(rootHash, "rootHash must not be null nor empty");
    Objects.requireNonNull(seedData, "seedData cannot be null");
    Objects.requireNonNull(proof, "proof cannot be null");
    if (proof.size() > ALLOWED_MAX_PROOF_DEPTH) {
      throw new IllegalArgumentException(
          "proof cannot have more than allowed maximum proof depth of " + ALLOWED_MAX_PROOF_DEPTH);
    }
    validateProofElements(proof);

    var hash = computeLeafHash(seedData, leafData);
    for (var siblingHash : proof) {
      hash = computePairHash(hash, siblingHash);
    }
    return Arrays.equals(rootHash, hash);
  }

  private static void validateProofElements(List<byte[]> proof) {
    for (var p : proof) {
      if (p == null || p.length != PADDING_ELEM_NUM_BYTES) {
        throw new IllegalArgumentException("Invalid proof element");
      }
    }
  }

  private static void requireNonNullAndNonEmptyBytes(byte[] data, String errorMessage) {
    if (data == null || data.length == 0) {
      throw new IllegalArgumentException(errorMessage);
    }
  }
}
