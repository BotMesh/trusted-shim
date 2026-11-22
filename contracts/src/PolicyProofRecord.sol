// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IZKMVerifierWithHash} from "@ziren/IZKMVerifier.sol";

/// Records cryptographic evidence of a pinned policy guest's computation.
/// An event is not authorization: policy ownership, freshness, budgets and
/// single-use execution remain the central ledger's responsibility.
contract PolicyProofRecord {
    IZKMVerifierWithHash public immutable verifier;
    bytes32 public immutable programVKey;

    event PolicyProofVerified(bytes32 indexed programVKey, bytes32 indexed publicValuesSha256);

    constructor(IZKMVerifierWithHash verifier_, bytes32 programVKey_, bytes32 expectedVerifierHash) {
        require(programVKey_ != bytes32(0), "empty program key");
        require(verifier_.VERIFIER_HASH() == expectedVerifierHash, "wrong circuit release");
        verifier = verifier_;
        programVKey = programVKey_;
    }

    function record(bytes calldata publicValues, bytes calldata proof) external {
        require(proof.length == 260 && publicValues.length > 0 && publicValues.length <= 65536, "invalid input");
        verifier.verifyProof(programVKey, publicValues, proof);
        emit PolicyProofVerified(programVKey, sha256(publicValues));
    }
}
