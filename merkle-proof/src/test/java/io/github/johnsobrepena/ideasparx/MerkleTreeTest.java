/*
 * Copyright (c) 2026 John Eric Sobrepena
 * SPDX-License-Identifier: MIT
 */
package io.github.johnsobrepena.ideasparx;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("MerkleTree Given-And-When-Then Specification Suite")
class MerkleTreeTest {

  @Nested
  @DisplayName("Constructor & Input Validation Specifications")
  class ConstructorValidationTests {

    @Test
    @DisplayName(
        "Given null or empty leaves set, when constructing tree, then throw IllegalArgumentException")
    void givenNullOrEmptyLeaves_whenConstructingTree_thenThrowIllegalArgumentException() {
      assertThrows(IllegalArgumentException.class, () -> new MerkleTree(null));
      assertThrows(IllegalArgumentException.class, () -> new MerkleTree(Set.of()));
    }

    @Test
    @DisplayName(
        "Given a null leaf element, when constructing tree, then throw IllegalArgumentException")
    void givenNullLeafElement_whenConstructingTree_thenThrowIllegalArgumentException() {
      Set<byte[]> leaves = new HashSet<>();
      leaves.add(new byte[] {1, 2, 3});
      leaves.add(null);

      assertThrows(IllegalArgumentException.class, () -> new MerkleTree(leaves));
    }

    @Test
    @DisplayName(
        "Given duplicate leaf byte content, when constructing tree, then throw IllegalArgumentException")
    void givenDuplicateLeafContent_whenConstructingTree_thenThrowIllegalArgumentException() {
      byte[] data1 = new byte[] {10, 20, 30};
      byte[] data2 = new byte[] {10, 20, 30}; // Separate array instance, identical byte content

      Set<byte[]> leaves = new HashSet<>();
      leaves.add(data1);
      leaves.add(data2);

      if (leaves.size() == 2) {
        assertThrows(IllegalArgumentException.class, () -> new MerkleTree(leaves));
      }
    }
  }

  @Nested
  @DisplayName("Tree Construction & Proof Verification Specifications")
  class TreeConstructionTests {

    @Test
    @DisplayName(
        "Given a single leaf, when building tree and verifying proof, then verification succeeds")
    void givenSingleLeaf_whenBuildingTreeAndVerifyingProof_thenVerificationSucceeds() {
      byte[] leafData = Util.generateID(32);
      Set<byte[]> leaves = Set.of(leafData);

      MerkleTree tree = new MerkleTree(leaves, 10, true);
      byte[] rootHash = tree.getRoot();

      assertNotNull(rootHash);
      assertEquals(32, rootHash.length);

      List<MerkleTree.Proof> proofs = tree.getProofs();
      assertEquals(1, proofs.size());

      MerkleTree.Proof proof = proofs.get(0);
      assertArrayEquals(leafData, proof.leaf().data());

      boolean verified =
          MerkleTree.verifyProof(
              proof.leaf().data(), proof.leaf().seed(), rootHash, proof.siblingHashes());
      assertTrue(verified, "Single-leaf proof verification should pass");
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 32, 100})
    @DisplayName(
        "Given leaf set sizes (N=1..100), when building tree and verifying proofs, then all proofs verify successfully")
    void givenVariousLeafSetSizes_whenBuildingTreeAndVerifyingProofs_thenAllProofsVerify(
        int count) {
      Set<byte[]> leaves = Util.getRandomIDs(count);

      MerkleTree tree = new MerkleTree(leaves, 10, true);
      byte[] root = tree.getRoot();

      List<MerkleTree.Proof> proofs = tree.getProofs();
      assertEquals(count, proofs.size());

      for (MerkleTree.Proof proof : proofs) {
        boolean verified =
            MerkleTree.verifyProof(
                proof.leaf().data(), proof.leaf().seed(), root, proof.siblingHashes());
        assertTrue(verified, "Verification failed for leaf count: " + count);
      }
    }

    @Test
    @DisplayName(
        "Given non-secure seed flag set to false, when building tree, then leaf seeds are empty and proofs verify successfully")
    void givenNonSecureSeedFlag_whenBuildingTree_thenSeedsAreEmptyAndProofsVerify() {
      Set<byte[]> leaves = Util.getRandomIDs(10);

      MerkleTree tree = new MerkleTree(leaves, 10, false);
      byte[] root = tree.getRoot();

      for (MerkleTree.Proof proof : tree.getProofs()) {
        assertEquals(
            0,
            proof.leaf().seed().length,
            "Seed should be empty byte array when useSecureSeed is false");
        boolean verified =
            MerkleTree.verifyProof(
                proof.leaf().data(), proof.leaf().seed(), root, proof.siblingHashes());
        assertTrue(verified, "Proof verification failed for non-secure seed tree");
      }
    }
  }

  @Nested
  @DisplayName("Proof Retrieval Specifications")
  class ProofRetrievalTests {

    @Test
    @DisplayName(
        "Given valid leaf data payload, when calling getProof, then return matching proof path")
    void givenValidLeafData_whenGettingProof_thenReturnMatchingProofPath() {
      Set<byte[]> leaves = Util.getRandomIDs(5);
      MerkleTree tree = new MerkleTree(leaves);

      byte[] targetData = leaves.iterator().next();

      List<byte[]> proofPath = tree.getProof(targetData);
      assertNotNull(proofPath);

      MerkleTree.Leaf matchingLeaf =
          tree.getProofs().stream()
              .map(MerkleTree.Proof::leaf)
              .filter(l -> Arrays.equals(l.data(), targetData))
              .findFirst()
              .orElseThrow();

      boolean verified =
          MerkleTree.verifyProof(targetData, matchingLeaf.seed(), tree.getRoot(), proofPath);
      assertTrue(verified, "getProof(targetData) returned invalid proof path");
    }

    @Test
    @DisplayName(
        "Given non-existent leaf data payload, when calling getProof, then throw NoSuchElementException")
    void givenNonExistentLeafData_whenGettingProof_thenThrowNoSuchElementException() {
      Set<byte[]> leaves = Set.of(Util.generateID(32), Util.generateID(32));
      MerkleTree tree = new MerkleTree(leaves);

      byte[] unknownData = Util.generateID(32);
      assertThrows(NoSuchElementException.class, () -> tree.getProof(unknownData));
    }

    @Test
    @DisplayName(
        "Given null or empty payload, when calling getProof, then throw IllegalArgumentException")
    void givenNullOrEmptyPayload_whenGettingProof_thenThrowIllegalArgumentException() {
      Set<byte[]> leaves = Set.of(Util.generateID(32));
      MerkleTree tree = new MerkleTree(leaves);

      assertThrows(IllegalArgumentException.class, () -> tree.getProof(null));
      assertThrows(IllegalArgumentException.class, () -> tree.getProof(new byte[0]));
    }
  }

  @Nested
  @DisplayName("Negative & Security Specifications")
  class NegativeSecurityTests {

    @Test
    @DisplayName("Given tampered leaf data, when verifying proof, then return false")
    void givenTamperedLeafData_whenVerifyingProof_thenReturnFalse() {
      Set<byte[]> leaves = Util.getRandomIDs(4);
      MerkleTree tree = new MerkleTree(leaves);

      MerkleTree.Proof proof = tree.getProofs().get(0);
      byte[] tamperedData = proof.leaf().data().clone();
      tamperedData[0] ^= (byte) 0xFF;

      boolean verified =
          MerkleTree.verifyProof(
              tamperedData, proof.leaf().seed(), tree.getRoot(), proof.siblingHashes());
      assertFalse(verified, "Tampered leaf data should fail verification");
    }

    @Test
    @DisplayName("Given tampered seed data, when verifying proof, then return false")
    void givenTamperedSeedData_whenVerifyingProof_thenReturnFalse() {
      Set<byte[]> leaves = Util.getRandomIDs(4);
      MerkleTree tree = new MerkleTree(leaves);

      MerkleTree.Proof proof = tree.getProofs().get(0);
      byte[] tamperedSeed = proof.leaf().seed().clone();
      if (tamperedSeed.length > 0) {
        tamperedSeed[0] ^= (byte) 0xFF;

        boolean verified =
            MerkleTree.verifyProof(
                proof.leaf().data(), tamperedSeed, tree.getRoot(), proof.siblingHashes());
        assertFalse(verified, "Tampered seed data should fail verification");
      }
    }

    @Test
    @DisplayName("Given tampered root hash, when verifying proof, then return false")
    void givenTamperedRootHash_whenVerifyingProof_thenReturnFalse() {
      Set<byte[]> leaves = Util.getRandomIDs(4);
      MerkleTree tree = new MerkleTree(leaves);

      MerkleTree.Proof proof = tree.getProofs().get(0);
      byte[] tamperedRoot = tree.getRoot();
      tamperedRoot[0] ^= (byte) 0xFF;

      boolean verified =
          MerkleTree.verifyProof(
              proof.leaf().data(), proof.leaf().seed(), tamperedRoot, proof.siblingHashes());
      assertFalse(verified, "Tampered root hash should fail verification");
    }

    @Test
    @DisplayName("Given tampered proof node, when verifying proof, then return false")
    void givenTamperedProofNode_whenVerifyingProof_thenReturnFalse() {
      Set<byte[]> leaves = Util.getRandomIDs(4);
      MerkleTree tree = new MerkleTree(leaves);

      MerkleTree.Proof proof = tree.getProofs().get(0);
      List<byte[]> tamperedSiblingHashes = new ArrayList<>(proof.siblingHashes());
      byte[] tamperedNode = tamperedSiblingHashes.get(0).clone();
      tamperedNode[0] ^= (byte) 0xFF;
      tamperedSiblingHashes.set(0, tamperedNode);

      boolean verified =
          MerkleTree.verifyProof(
              proof.leaf().data(), proof.leaf().seed(), tree.getRoot(), tamperedSiblingHashes);
      assertFalse(verified, "Tampered proof node should fail verification");
    }
  }

  @Nested
  @DisplayName("Immutability Specifications")
  class ImmutabilityTests {

    @Test
    @DisplayName(
        "Given tree root, when mutating returned root array, then internal root hash remains unchanged")
    void givenTreeRoot_whenMutatingReturnedRootArray_thenInternalRootHashIsUnchanged() {
      MerkleTree tree = new MerkleTree(Set.of(Util.generateID(32)));
      byte[] root1 = tree.getRoot();
      byte[] root2 = tree.getRoot();

      assertArrayEquals(root1, root2);
      assertNotSame(root1, root2, "getRoot() should return a new cloned array reference");

      root1[0] ^= (byte) 0xFF;
      assertFalse(
          Arrays.equals(root1, tree.getRoot()),
          "Mutating getRoot() return should not alter internal root");
    }
  }
}
