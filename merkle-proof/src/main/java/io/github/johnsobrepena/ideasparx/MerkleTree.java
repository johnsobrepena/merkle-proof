/*
 * Copyright (c) 2026 John Eric Sobrepena
 * SPDX-License-Identifier: MIT
 */
package io.github.johnsobrepena.ideasparx;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;

/**
 * Merkle Tree with salted leaves and optional depth padding. Thread-safe. Immutable after
 * construction.
 */
public final class MerkleTree {

  private static final int SEED_NUM_BYTES = 32;
  private static final int PADDING_ELEM_NUM_BYTES = 32;
  private static final int DEFAULT_MIN_PROOF_DEPTH = 0;
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
   * Construct tree with default depth (no padding) and secure seeds.
   *
   * @param leaves Set of unique leaf payload byte arrays.
   * @throws IllegalArgumentException If leaves is null, empty, contains null, or has duplicate
   *     content.
   */
  public MerkleTree(Set<byte[]> leaves) {
    this(leaves, DEFAULT_MIN_PROOF_DEPTH, true);
  }

  /**
   * Construct tree with custom target depth and seed option.
   *
   * @param leaves Set of unique leaf payload byte arrays.
   * @param targetProofDepth Target minimum depth for proof padding (0 for no padding).
   * @param useSecureSeed Enable random 32-byte salt seeds per leaf if true.
   * @throws IllegalArgumentException If leaves is null, empty, contains null, or has duplicate
   *     content.
   */
  public MerkleTree(Set<byte[]> leaves, int targetProofDepth, boolean useSecureSeed) {
    if (leaves == null || leaves.isEmpty()) {
      throw new IllegalArgumentException("Leaves must not be null or empty");
    }
    this.proofPaddings = new ArrayList<>();
    this.targetProofDepth = targetProofDepth;
    this.useSecureSeed = useSecureSeed;
    this.layers = new ArrayList<>();

    Map<ByteBuffer, Integer> indexMap = new HashMap<>();
    List<Leaf> leafList = new ArrayList<>(leaves.size());

    int index = 0;
    for (var leafData : leaves) {
      if (leafData == null) {
        throw new IllegalArgumentException("Leaf data element must not be null");
      }
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
        this.seededLeaves.stream().map(leaf -> computePairHash(leaf.seed, leaf.data)).toList();

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
   * Get proof record (Leaf + sibling hashes) for specific leaf payload. O(1) lookup.
   *
   * @param leafData Raw leaf payload bytes to search.
   * @return Proof instance containing Leaf and list of sibling hashes.
   * @throws IllegalArgumentException If leafData is null or empty.
   * @throws NoSuchElementException If leafData not found in tree.
   */
  public Proof getProof(byte[] leafData) {
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
    if (leafData == null || leafData.length == 0) {
      throw new IllegalArgumentException("leafData must not be null nor empty");
    }
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
    try {
      byte[] left, right;
      if (Arrays.compare(input1, input2) > 0) {
        left = input2;
        right = input1;
      } else {
        left = input1;
        right = input2;
      }

      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.update(left);
      md.update(right);
      return md.digest();
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
   * @return True if proof path reconstructs rootHash; false otherwise.
   */
  public static boolean verifyProof(
      byte[] leafData, byte[] seedData, byte[] rootHash, List<byte[]> proof) {
    var hash = computePairHash(leafData, seedData);
    for (var siblingHash : proof) {
      hash = computePairHash(hash, siblingHash);
    }
    return Arrays.equals(rootHash, hash);
  }
}
