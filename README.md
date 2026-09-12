# Merkle Tree Library 
(`io.github.johnsobrepena.ideasparx:merkle-proof`)

High-performance, thread-safe, privacy-preserving Merkle Tree implementation in Java 17+.

[![Java 17+](https://img.shields.io/badge/Java-17%2B-blue.svg)](https://jdk.java.net/17/)
[![Coverage >90%](https://img.shields.io/badge/Coverage-%3E90%25-green.svg)](#testing--quality)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Key Features

- **Zero External Runtime Dependencies** - Built entirely with pure Java 17 standard library components (`java.security.MessageDigest`, `java.security.SecureRandom`). Zero third-party runtime bloat, zero supply-chain attack vector.
- **Salted Leaf Security (Anti-Rainbow Table Defense)** - Assigns a 32-byte `SecureRandom` salt seed per leaf, preventing pre-image rainbow table and dictionary brute-force attacks on low-entropy leaf data (such as emails or user IDs).
- **Cryptographic Domain Separation & Canonical Hashing** - Prepends domain prefix tags (`0x00` for leaves, `0x01` for internal nodes) and lexicographically sorts child pairs before SHA-256 hashing, eliminating replay and second pre-image vulnerabilities.
- **$O(1)$ Instant Proof Lookups** - Internal `Map<ByteBuffer, Integer>` indexing allows constant-time proof path retrieval by leaf payload without $O(N)$ tree scanning.
- **Side-Channel Anonymity via Depth Padding** - Optional `targetProofDepth` (capped at 20) pads audit paths with secure dummy hashes to uniform lengths, hiding tree scale and leaf index from proof verifiers.
- **Strict Byte-Content Set Uniqueness & Size Bounding** - Enforces content-level deduplication (`ByteBuffer.wrap()`) and caps leaf count at 1,048,576 ($2^{20}$) to guarantee tree integrity and deterministic verification limits.
- **Thread-Safe & Zero-Copy Architecture** - Powered by Java 17 `record` types (`Leaf`, `Proof`), unmodifiable collection wrappers, and zero-copy design for safe, low-GC multi-threaded concurrency.

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
- `getProofsAsMap()`: Returns an unmodifiable map of leaf payload `ByteBuffer` to `Proof` records for fast bulk lookup.
- `getProof(byte[] leafData)`: $O(1)$ fast lookup returning the `Proof` record containing the `Leaf` (with salt seed and leaf data) and its `siblingHashes`.
- `getSiblingHashes(byte[] leafData)`: $O(1)$ fast lookup returning the unmodifiable list of 32-byte sibling hashes along the proof path.
- `verifyProof(byte[] leafData, byte[] seedData, byte[] rootHash, List<byte[]> proof)`: Static utility verifying proof path validity against root hash.

---

## Security Architecture & Design Rationale

This library balances cryptographic security with high-throughput, zero-copy performance:

- **Domain Separation & Length Prefixing** - Leaf hashing prepends `0x00` with explicit length headers (`0x00 || len(seed) || seed || len(data) || data`), while internal nodes prepend `0x01` (`0x01 || left || right`). This mathematically guarantees that internal node hashes cannot be replayed as leaf proofs.
- **Zero-Copy & Low GC Overhead** - Padding elements and leaf arrays are shared directly without defensive deep-cloning on every retrieval. The library targets high-throughput microservices where allocation pressure degrades latency; callers are expected to treat returned proof byte arrays as read-only.
- **Lean Records** - `Leaf` and `Proof` records deliberately omit custom `.equals()` and `.hashCode()` overrides to avoid unused boilerplate and code bloat, as internal lookups rely on `ByteBuffer` indexing rather than record hashing.
- **Fail-Fast Invariant Enforcement** - `verifyProof` enforces strict contract invariants (non-null, exact 32-byte hashes, max depth $\le 20$) and throws `IllegalArgumentException` / `NullPointerException` on violations, rather than returning false and masking caller bugs. Tree leaf counts are similarly capped at `ALLOWED_MAX_LEAF_COUNT = 1,048,576` ($2^{20}$) in the constructor so natural depth never exceeds the verifier limit.
- **Depth Padding Scope** - Optional `targetProofDepth` (capped at 20) hides tree scale and leaf position from an isolated verifier. Because padding is applied at the tree root, colluding verifiers comparing proofs can observe matching trailing dummy hashes.

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
