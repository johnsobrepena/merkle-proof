/*
 * Copyright (c) 2026 John Eric Sobrepena
 * SPDX-License-Identifier: MIT
 */
package io.github.johnsobrepena.ideasparx;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
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

      assertEquals(2, leaves.size(), "Set should contain both array instances");
      assertThrows(IllegalArgumentException.class, () -> new MerkleTree(leaves));
    }

    @Test
    @DisplayName(
        "Given empty leaf element, when constructing tree, then throw IllegalArgumentException")
    void givenEmptyLeafElement_whenConstructingTree_thenThrowIllegalArgumentException() {
      Set<byte[]> leaves = new HashSet<>();
      leaves.add(new byte[0]);

      assertThrows(IllegalArgumentException.class, () -> new MerkleTree(leaves));
    }

    @Test
    @DisplayName(
        "Given negative target proof depth, when constructing tree, then throw IllegalArgumentException")
    void givenNegativeTargetProofDepth_whenConstructingTree_thenThrowIllegalArgumentException() {
      Set<byte[]> leaves = Set.of(generateID(32));
      assertThrows(IllegalArgumentException.class, () -> new MerkleTree(leaves, -1, true));
    }

    @Test
    @DisplayName(
        "Given target proof depth exceeding allowed maximum, when constructing tree, then throw IllegalArgumentException")
    void
        givenTargetProofDepthExceedingMax_whenConstructingTree_thenThrowIllegalArgumentException() {
      Set<byte[]> leaves = Set.of(generateID(32));
      assertThrows(
          IllegalArgumentException.class,
          () -> new MerkleTree(leaves, MerkleTree.ALLOWED_MAX_PROOF_DEPTH + 1, true));
    }

    @Test
    @DisplayName(
        "Given leaves set exceeding allowed maximum leaf count, when constructing tree, then throw IllegalArgumentException")
    void
        givenLeavesSetExceedingMaxLeafCount_whenConstructingTree_thenThrowIllegalArgumentException() {
      Set<byte[]> oversizedSet =
          new AbstractSet<>() {
            @Override
            public Iterator<byte[]> iterator() {
              return Collections.emptyIterator();
            }

            @Override
            public int size() {
              return MerkleTree.ALLOWED_MAX_LEAF_COUNT + 1;
            }

            @Override
            public boolean isEmpty() {
              return false;
            }
          };

      var ex = assertThrows(IllegalArgumentException.class, () -> new MerkleTree(oversizedSet));
      assertTrue(
          ex.getMessage()
              .contains(
                  "Leaves count cannot exceed allowed maximum of "
                      + MerkleTree.ALLOWED_MAX_LEAF_COUNT));
    }
  }

  @Nested
  @DisplayName("Tree Construction & Proof Verification Specifications")
  class TreeConstructionTests {

    @Test
    @DisplayName(
        "Given a single leaf, when building tree and verifying proof, then verification succeeds")
    void givenSingleLeaf_whenBuildingTreeAndVerifyingProof_thenVerificationSucceeds() {
      byte[] leafData = generateID(32);
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
      Set<byte[]> leaves = getRandomIDs(count);

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
      Set<byte[]> leaves = getRandomIDs(10);

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

    @Test
    @DisplayName(
        "Given default tree constructor, when retrieving proofs, then proof path is padded to DEFAULT_MIN_PROOF_DEPTH")
    void givenDefaultConstructor_whenRetrievingProofs_thenProofPathIsPaddedToDefaultMinDepth() {
      Set<byte[]> leaves = getRandomIDs(1);
      MerkleTree tree = new MerkleTree(leaves);

      MerkleTree.Proof proof = tree.getProofs().get(0);
      assertEquals(
          MerkleTree.DEFAULT_MIN_PROOF_DEPTH - 1,
          proof.siblingHashes().size(),
          "Proof path length must equal DEFAULT_MIN_PROOF_DEPTH - 1 for single-leaf tree");
    }
  }

  @Nested
  @DisplayName("Proof Retrieval Specifications")
  class ProofRetrievalTests {

    @Test
    @DisplayName(
        "Given valid leaf data payload, when calling getProof, then return matching Proof record")
    void givenValidLeafData_whenGettingProof_thenReturnMatchingProofRecord() {
      Set<byte[]> leaves = getRandomIDs(5);
      MerkleTree tree = new MerkleTree(leaves);

      byte[] targetData = leaves.iterator().next();

      MerkleTree.Proof proof = tree.getProof(targetData);
      assertNotNull(proof);
      assertArrayEquals(targetData, proof.leaf().data());

      boolean verified =
          MerkleTree.verifyProof(
              proof.leaf().data(), proof.leaf().seed(), tree.getRoot(), proof.siblingHashes());
      assertTrue(verified, "getProof(targetData) returned invalid proof object");
    }

    @Test
    @DisplayName(
        "Given valid leaf data payload, when calling getSiblingHashes, then return matching proof path")
    void givenValidLeafData_whenGettingSiblingHashes_thenReturnMatchingProofPath() {
      Set<byte[]> leaves = getRandomIDs(5);
      MerkleTree tree = new MerkleTree(leaves);

      byte[] targetData = leaves.iterator().next();

      List<byte[]> siblingHashes = tree.getSiblingHashes(targetData);
      assertNotNull(siblingHashes);

      MerkleTree.Leaf matchingLeaf =
          tree.getProofs().stream()
              .map(MerkleTree.Proof::leaf)
              .filter(l -> Arrays.equals(l.data(), targetData))
              .findFirst()
              .orElseThrow();

      boolean verified =
          MerkleTree.verifyProof(targetData, matchingLeaf.seed(), tree.getRoot(), siblingHashes);
      assertTrue(verified, "getSiblingHashes(targetData) returned invalid sibling hashes path");
    }

    @Test
    @DisplayName(
        "Given non-existent leaf data payload, when calling getProof or getSiblingHashes, then throw NoSuchElementException")
    void
        givenNonExistentLeafData_whenGettingProofOrSiblingHashes_thenThrowNoSuchElementException() {
      Set<byte[]> leaves = Set.of(generateID(32), generateID(32));
      MerkleTree tree = new MerkleTree(leaves);

      byte[] unknownData = generateID(32);
      assertThrows(NoSuchElementException.class, () -> tree.getProof(unknownData));
      assertThrows(NoSuchElementException.class, () -> tree.getSiblingHashes(unknownData));
    }

    @Test
    @DisplayName(
        "Given null or empty payload, when calling getProof or getSiblingHashes, then throw IllegalArgumentException")
    void
        givenNullOrEmptyPayload_whenGettingProofOrSiblingHashes_thenThrowIllegalArgumentException() {
      Set<byte[]> leaves = Set.of(generateID(32));

      MerkleTree tree = new MerkleTree(leaves);

      assertThrows(IllegalArgumentException.class, () -> tree.getProof(null));
      assertThrows(IllegalArgumentException.class, () -> tree.getProof(new byte[0]));
      assertThrows(IllegalArgumentException.class, () -> tree.getSiblingHashes(null));
      assertThrows(IllegalArgumentException.class, () -> tree.getSiblingHashes(new byte[0]));
    }

    @Test
    @DisplayName(
        "Given valid tree, when calling getProofsAsMap, then return all valid proof mappings")
    void givenValidTree_whenGettingProofsAsMap_thenReturnAllValidProofMappings() {
      Set<byte[]> leaves = getRandomIDs(5);
      MerkleTree tree = new MerkleTree(leaves);

      Map<ByteBuffer, MerkleTree.Proof> proofsMap = tree.getProofsAsMap();
      assertEquals(5, proofsMap.size());

      for (byte[] leafData : leaves) {
        MerkleTree.Proof proof = proofsMap.get(ByteBuffer.wrap(leafData));
        assertNotNull(proof);
        assertArrayEquals(leafData, proof.leaf().data());

        boolean verified =
            MerkleTree.verifyProof(
                proof.leaf().data(), proof.leaf().seed(), tree.getRoot(), proof.siblingHashes());
        assertTrue(verified);
      }
    }

    @Test
    @DisplayName(
        "Given non-secure seed tree, when calling getProofsAsMap, then return full map without key collision")
    void givenNonSecureSeedTree_whenGettingProofsAsMap_thenReturnFullMapWithoutCollision() {
      Set<byte[]> leaves = getRandomIDs(5);
      MerkleTree tree = new MerkleTree(leaves, 0, false);

      Map<ByteBuffer, MerkleTree.Proof> proofsMap = tree.getProofsAsMap();
      assertEquals(
          5, proofsMap.size(), "Map size must equal total leaf count when useSecureSeed is false");
    }

    @Test
    @DisplayName(
        "Given returned proofs map, when attempting mutation, then throw UnsupportedOperationException")
    void givenReturnedProofsMap_whenAttemptingMutation_thenThrowUnsupportedOperationException() {
      MerkleTree tree = new MerkleTree(getRandomIDs(3));
      Map<ByteBuffer, MerkleTree.Proof> proofsMap = tree.getProofsAsMap();

      assertThrows(UnsupportedOperationException.class, () -> proofsMap.clear());
    }
  }

  @Nested
  @DisplayName("Negative & Security Specifications")
  class NegativeSecurityTests {

    @Test
    @DisplayName("Given tampered leaf data, when verifying proof, then return false")
    void givenTamperedLeafData_whenVerifyingProof_thenReturnFalse() {
      Set<byte[]> leaves = getRandomIDs(4);
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
      Set<byte[]> leaves = getRandomIDs(4);
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
      Set<byte[]> leaves = getRandomIDs(4);
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
      Set<byte[]> leaves = getRandomIDs(4);
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

    @Test
    @DisplayName(
        "Given null or empty arguments, when verifying proof, then throw expected exceptions")
    void givenNullOrEmptyArguments_whenVerifyingProof_thenThrowExpectedExceptions() {
      byte[] leaf = generateID(32);
      byte[] seed = generateID(32);
      byte[] root = generateID(32);
      List<byte[]> proof = List.of(generateID(32));

      assertThrows(
          IllegalArgumentException.class, () -> MerkleTree.verifyProof(null, seed, root, proof));
      assertThrows(
          IllegalArgumentException.class,
          () -> MerkleTree.verifyProof(new byte[0], seed, root, proof));
      assertThrows(
          IllegalArgumentException.class, () -> MerkleTree.verifyProof(leaf, seed, null, proof));
      assertThrows(
          IllegalArgumentException.class,
          () -> MerkleTree.verifyProof(leaf, seed, new byte[0], proof));
      assertThrows(
          NullPointerException.class, () -> MerkleTree.verifyProof(leaf, null, root, proof));
      assertThrows(
          NullPointerException.class, () -> MerkleTree.verifyProof(leaf, seed, root, null));
    }

    @Test
    @DisplayName(
        "Given proof exceeding allowed maximum depth, when verifying proof, then throw IllegalArgumentException")
    void givenProofExceedingMaxDepth_whenVerifyingProof_thenThrowIllegalArgumentException() {
      byte[] leaf = generateID(32);
      byte[] seed = generateID(32);
      byte[] root = generateID(32);

      List<byte[]> excessiveProof = new ArrayList<>();
      for (int i = 0; i < MerkleTree.ALLOWED_MAX_PROOF_DEPTH + 1; i++) {
        excessiveProof.add(generateID(32));
      }

      var ex =
          assertThrows(
              IllegalArgumentException.class,
              () -> MerkleTree.verifyProof(leaf, seed, root, excessiveProof));
      assertTrue(
          ex.getMessage()
              .contains("allowed maximum proof depth of " + MerkleTree.ALLOWED_MAX_PROOF_DEPTH));
    }

    @Test
    @DisplayName(
        "Given proof with null or non-32-byte elements, when verifying proof, then throw IllegalArgumentException")
    void
        givenProofWithNullOrNon32ByteElements_whenVerifyingProof_thenThrowIllegalArgumentException() {
      byte[] leaf = generateID(32);
      byte[] seed = generateID(32);
      byte[] root = generateID(32);

      List<byte[]> proofWithNull = Collections.singletonList(null);
      assertThrows(
          IllegalArgumentException.class,
          () -> MerkleTree.verifyProof(leaf, seed, root, proofWithNull));

      List<byte[]> proofWithShortHash = List.of(new byte[16]);
      assertThrows(
          IllegalArgumentException.class,
          () -> MerkleTree.verifyProof(leaf, seed, root, proofWithShortHash));

      List<byte[]> proofWithLongHash = List.of(new byte[64]);
      assertThrows(
          IllegalArgumentException.class,
          () -> MerkleTree.verifyProof(leaf, seed, root, proofWithLongHash));
    }

    @Test
    @DisplayName(
        "Given intermediate internal node replayed as leaf, when verifying proof, then verification fails")
    void givenInternalNodeReplay_whenVerifyingProof_thenReturnFalse() {
      Set<byte[]> leaves = getRandomIDs(4);
      MerkleTree tree = new MerkleTree(leaves);

      List<MerkleTree.Proof> proofs = tree.getProofs();
      // proofs.get(0) and proofs.get(1) are siblings in layer 0
      byte[] h0 = proofs.get(1).siblingHashes().get(0);
      byte[] h1 = proofs.get(0).siblingHashes().get(0);

      byte[] left, right;
      if (Arrays.compare(h0, h1) > 0) {
        left = h1;
        right = h0;
      } else {
        left = h0;
        right = h1;
      }

      List<byte[]> truncatedPath =
          proofs.get(0).siblingHashes().subList(1, proofs.get(0).siblingHashes().size());

      // Attacker attempts to replay internal node pair (left, right) as (leafData, seedData)
      boolean verified = MerkleTree.verifyProof(left, right, tree.getRoot(), truncatedPath);
      assertFalse(
          verified,
          "Domain separation (0x00 vs 0x01) must prevent intermediate nodes from verifying as leaves");
    }

    @Test
    @DisplayName(
        "Given concatenation forgery attempt on non-secure seed tree, when verifying proof, then verification fails")
    void givenConcatenationForgery_whenVerifyingProof_thenReturnFalse() {
      Set<byte[]> leaves = getRandomIDs(4);
      MerkleTree tree = new MerkleTree(leaves, 0, false);

      List<MerkleTree.Proof> proofs = tree.getProofs();
      // proofs.get(0) and proofs.get(1) are siblings in layer 0
      byte[] h0 = proofs.get(1).siblingHashes().get(0);
      byte[] h1 = proofs.get(0).siblingHashes().get(0);

      byte[] left, right;
      if (Arrays.compare(h0, h1) > 0) {
        left = h1;
        right = h0;
      } else {
        left = h0;
        right = h1;
      }

      // Attacker concatenates sorted internal node pre-images: left (32 bytes) || right (32 bytes)
      byte[] forged64ByteLeaf = new byte[64];
      System.arraycopy(left, 0, forged64ByteLeaf, 0, 32);
      System.arraycopy(right, 0, forged64ByteLeaf, 32, 32);

      List<byte[]> truncatedPath =
          proofs.get(0).siblingHashes().subList(1, proofs.get(0).siblingHashes().size());

      boolean verified =
          MerkleTree.verifyProof(forged64ByteLeaf, new byte[0], tree.getRoot(), truncatedPath);
      assertFalse(
          verified,
          "Domain separation and length prefixing must prevent 64-byte concatenation forgery");
    }
  }

  @Nested
  @DisplayName("Immutability Specifications")
  class ImmutabilityTests {

    @Test
    @DisplayName(
        "Given tree root, when mutating returned root array, then internal root hash remains unchanged")
    void givenTreeRoot_whenMutatingReturnedRootArray_thenInternalRootHashIsUnchanged() {
      MerkleTree tree = new MerkleTree(Set.of(generateID(32)));
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

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private static byte[] generateID(int length) {
    byte[] bytes = new byte[length];
    SECURE_RANDOM.nextBytes(bytes);
    return bytes;
  }

  private static Set<byte[]> getRandomIDs(int count) {
    Set<byte[]> members = new LinkedHashSet<>();
    for (int i = 0; i < count; i++) {
      members.add(generateID(32));
    }
    return members;
  }
}
