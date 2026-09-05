/*
 * Copyright (c) 2026 John Eric Sobrepena
 * SPDX-License-Identifier: MIT
 */
package io.github.johnsobrepena.ideasparx;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Demo application demonstrating Merkle Tree Privacy-Preserving Membership Proofs.
 *
 * <p>Scenario: An organization maintains a set of 5 authorized member IDs (Alice, Bob, Charlie,
 * David, Eve). The organization publishes ONLY the 32-byte Merkle Root Hash publicly.
 *
 * <p>Member "Charlie" wants to prove membership to a 3rd party Verifier WITHOUT revealing the
 * identities or hashes of Alice, Bob, David, or Eve.
 */
public class App {

  public static void main(String[] args) {
    System.out.println(
        "================================================================================");
    System.out.println(
        "          MERKLE TREE PRIVACY-PRESERVING MEMBERSHIP PROOF DEMO                  ");
    System.out.println(
        "================================================================================");

    // Define authorized members (5 distinct user payloads)
    byte[] aliceData = "USER_ID_ALICE_1001".getBytes(StandardCharsets.UTF_8);
    byte[] bobData = "USER_ID_BOB_1002".getBytes(StandardCharsets.UTF_8);
    byte[] charlieData = "USER_ID_CHARLIE_1003".getBytes(StandardCharsets.UTF_8);
    byte[] davidData = "USER_ID_DAVID_1004".getBytes(StandardCharsets.UTF_8);
    byte[] eveData = "USER_ID_EVE_1005".getBytes(StandardCharsets.UTF_8);

    Set<byte[]> authorizedMembers =
        new LinkedHashSet<>(List.of(aliceData, bobData, charlieData, davidData, eveData));

    // Issuer constructs the Merkle Tree and publishes ONLY the public root hash
    MerkleTree merkleTree = new MerkleTree(authorizedMembers, 10, true);
    byte[] publicRootHash = merkleTree.getRoot();

    System.out.println("\n[STEP 1: Issuer Publishing Public State]");
    System.out.println("Total Authorized Whitelist Members : " + authorizedMembers.size());
    System.out.println("Published Public Merkle Root Hash  : 0x" + toHex(publicRootHash));

    // Prover extracts a specific proof for Charlie
    List<byte[]> charlieProofPath = merkleTree.getProof(charlieData);
    MerkleTree.Proof charlieProof =
        merkleTree.getProofs().stream()
            .filter(p -> Arrays.equals(p.leaf().data(), charlieData))
            .findFirst()
            .orElseThrow();

    System.out.println("\n[STEP 2: Prover Generating Private Proof for 'Charlie']");
    System.out.println(
        "Prover Payload (Charlie Data)      : "
            + new String(charlieProof.leaf().data(), StandardCharsets.UTF_8));
    System.out.println(
        "Prover Salt Seed                   : 0x" + toHex(charlieProof.leaf().seed()));
    System.out.println(
        "Audit Path Proof Size (Nodes)      : " + charlieProofPath.size() + " hashes");
    System.out.println("\nProof Path Hashes (Intermediate Sibling Hashes):");
    for (int i = 0; i < charlieProofPath.size(); i++) {
      System.out.println("  Node [" + i + "]: 0x" + toHex(charlieProofPath.get(i)));
    }

    // Verifier receives ONLY (charlieData, charlieSeed, publicRootHash, charlieProofPath)
    System.out.println("\n[STEP 3: Verifier Cryptographic Verification]");
    System.out.println(
        "Notice: The Verifier ONLY sees Charlie's data + 32-byte intermediate node hashes.");
    System.out.println(
        "The Verifier DOES NOT learn the existence, names, or IDs of Alice, Bob, David, or Eve!");

    boolean isVerified =
        MerkleTree.verifyProof(
            charlieProof.leaf().data(),
            charlieProof.leaf().seed(),
            publicRootHash,
            charlieProofPath);

    System.out.println(
        "\nVerification Result: " + (isVerified ? "SUCCESS [PASSED]" : "FAILED [FAILED]"));
    System.out.println("Charlie's membership is cryptographically proven against the public root!");
    System.out.println(
        "================================================================================");
  }

  private static String toHex(byte[] bytes) {
    return HexFormat.of().formatHex(bytes);
  }
}
