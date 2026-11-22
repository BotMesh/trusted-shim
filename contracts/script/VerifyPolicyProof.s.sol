// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {PolicyFixture} from "../test/PolicyProof.t.sol";
import {ZKMVerifier} from "@ziren/v2.0.0/ZKMVerifierGroth16.sol";
import {PolicyProofRecord} from "../src/PolicyProofRecord.sol";

/// Deploy the unmodified upstream verifier and verify the receipt in a mined
/// transaction. The harness uses an isolated Anvil chain and unlocked test sender.
contract VerifyPolicyProof is PolicyFixture {
    function run() public {
        bytes32 expected = loadFixture();
        vm.startBroadcast();
        verifier = new ZKMVerifier();
        require(verifier.VERIFIER_HASH() == expected, "wrong circuit release");
        PolicyProofRecord record = new PolicyProofRecord(verifier, program, expected);
        record.record(publicValues, proof);
        vm.stopBroadcast();
    }
}
