# Merkle Tree Library 
(`io.github.johnsobrepena.ideasparx:merkle-proof`)

High-performance, thread-safe, privacy-preserving Merkle Tree implementation in Java 17+.

[![Java 17+](https://img.shields.io/badge/Java-17%2B-blue.svg)](https://jdk.java.net/17/)
[![Coverage >90%](https://img.shields.io/badge/Coverage-%3E90%25-green.svg)](#testing--quality)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Key Features

- **Zero External Runtime Dependencies**: Built entirely with pure Java 17 standard library components (`java.security.MessageDigest`, `java.security.SecureRandom`). Zero third-party runtime bloat, zero supply-chain attack vector.
- **Salted Leaf Security (Anti-Rainbow Table Defense)**: Assigns a 32-byte `SecureRandom` salt seed per leaf, preventing pre-image rainbow table and dictionary brute-force attacks on low-entropy leaf data (such as emails or user IDs).
- **Canonical Sorted-Pair Hashing**: Lexicographically sorts child node pairs before SHA-256 hashing (`Arrays.compare`), eliminating sibling ordering ambiguity and defending against second pre-image vulnerabilities.
- **$O(1)$ Instant Proof Lookups**: Internal `Map<ByteBuffer, Integer>` indexing allows constant-time proof path retrieval by leaf payload without $O(N)$ tree scanning.
- **Side-Channel Anonymity via Depth Padding**: Optional `targetProofDepth` pads audit paths with secure dummy hashes to uniform lengths, hiding tree scale and leaf index from proof verifiers.
- **Strict Byte-Content Set Uniqueness**: Enforces content-level deduplication (`ByteBuffer.wrap()`) rather than object reference checks to guarantee tree integrity.
- **Thread-Safe & Immutable Architecture**: Powered by Java 17 `record` types (`Leaf`, `Proof`), defensive array cloning, and unmodifiable collection wrappers for safe multi-threaded concurrency without lock contention.

---

## Requirements

- **Java Development Kit (JDK)**: 17 or higher
- **Gradle**: 8.0 or higher

---

## Usage Scenario: Privacy-Preserving Whitelist Membership Proof

### Scenario Overview
An organization maintains an authorized whitelist of member IDs (`Alice`, `Bob`, `Charlie`, `David`, `Eve`). The issuer publishes **only** the 32-byte Merkle Root Hash publicly to a public API, blockchain or smart contract.

Member **Charlie** needs to prove to a 3rd-party Verifier that he belongs to the whitelist **without revealing the names, IDs, or total count of other members**.

### Code Example

```java
package io.github.johnsobrepena.ideasparx;

import java.nio.charset.StandardCharsets;
import java.util.*;

public class UsageExample {

  public static void main(String[] args) {
    // Prepare unique member payloads
    byte[] aliceData   = "USER_ALICE_1001".getBytes(StandardCharsets.UTF_8);
    byte[] bobData     = "USER_BOB_1002".getBytes(StandardCharsets.UTF_8);
    byte[] charlieData = "USER_CHARLIE_1003".getBytes(StandardCharsets.UTF_8);
    byte[] davidData   = "USER_DAVID_1004".getBytes(StandardCharsets.UTF_8);
    byte[] eveData     = "USER_EVE_1005".getBytes(StandardCharsets.UTF_8);

    Set<byte[]> whitelistMembers = Set.of(aliceData, bobData, charlieData, davidData, eveData);

    // Issuer constructs Merkle Tree and publishes public root hash
    MerkleTree merkleTree = new MerkleTree(whitelistMembers);
    byte[] publicRootHash = merkleTree.getRoot();

    // Prover extracts Charlie's proof record (including salt seed) and audit path
    MerkleTree.Proof charlieProof = merkleTree.getProof(charlieData);
    List<byte[]> charlieProofPath = charlieProof.siblingHashes();
    MerkleTree.Leaf charlieLeaf = charlieProof.leaf();

    // Verifier receives ONLY (charlieData, charlieSeed, publicRootHash, charlieProofPath)
    // Verifier NEVER learns the identity of Alice, Bob, David, or Eve!
    boolean isVerified = MerkleTree.verifyProof(
        charlieLeaf.data(),
        charlieLeaf.seed(),
        publicRootHash,
        charlieProofPath
    );

    System.out.println("Charlie Membership Verified: " + isVerified); // true
  }
}
```

---

## API Reference

### `MerkleTree`
- `MerkleTree(Set<byte[]> leaves)`: Constructs tree using default parameters (secure 32-byte salt seeds).
- `MerkleTree(Set<byte[]> leaves, int targetProofDepth, boolean useSecureSeed)`: Custom constructor with target proof depth padding option.
- `getRoot()`: Returns a cloned 32-byte array of the root hash.
- `getProofs()`: Returns an unmodifiable list of `Proof(Leaf leaf, List<byte[]> siblingHashes)` records for all leaves.
- `getProof(byte[] leafData)`: $O(1)$ fast lookup returning the `Proof` record containing the `Leaf` (with salt seed and leaf data) and its `siblingHashes`.
- `getSiblingHashes(byte[] leafData)`: $O(1)$ fast lookup returning the unmodifiable list of 32-byte sibling hashes along the proof path.
- `verifyProof(byte[] leafData, byte[] seedData, byte[] rootHash, List<byte[]> proof)`: Static utility verifying proof path validity against root hash.

---

## Testing & Quality

Run full unit tests, Spotless code formatting checks, and JaCoCo >90% code coverage verification:

```bash
# Run unit tests & code quality checks
./gradlew check

# Run the interactive membership proof demo (located in ./examples)
./gradlew run
# Or run specifically via the examples subproject task
./gradlew :examples:run
```


---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright © 2026 John Eric Sobrepena
