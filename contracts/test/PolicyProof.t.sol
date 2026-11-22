// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ZKMVerifier} from "@ziren/v2.0.0/ZKMVerifierGroth16.sol";
import {PolicyProofRecord} from "../src/PolicyProofRecord.sol";

interface Vm {
    function envString(string calldata) external view returns (string memory);
    function readFile(string calldata) external view returns (string memory);
    function parseJsonBytes(string calldata, string calldata) external pure returns (bytes memory);
    function parseJsonBytes32(string calldata, string calldata) external pure returns (bytes32);
    function startBroadcast() external;
    function stopBroadcast() external;
}

abstract contract PolicyFixture {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    ZKMVerifier internal verifier;
    bytes32 internal program;
    bytes internal publicValues;
    bytes internal proof;

    function loadFixture() internal returns (bytes32 verifierHash) {
        string memory fixture = vm.readFile(vm.envString("TRUSTED_EVM_FIXTURE"));
        program = vm.parseJsonBytes32(fixture, ".programVkey");
        publicValues = vm.parseJsonBytes(fixture, ".publicValues");
        proof = vm.parseJsonBytes(fixture, ".proof");
        require(proof.length == 260 && publicValues.length > 0, "invalid fixture");
        return vm.parseJsonBytes32(fixture, ".verifierHash");
    }
}

/// Uses a real remote proof; no mocked verifier or local proof generator.
contract PolicyProofTest is PolicyFixture {
    PolicyProofRecord internal record;

    function setUp() public {
        bytes32 expected = loadFixture();
        verifier = new ZKMVerifier();
        require(verifier.VERIFIER_HASH() == expected, "wrong circuit release");
        record = new PolicyProofRecord(verifier, program, expected);
    }

    function testRemotePolicyProof() public view {
        verifier.verifyProof(program, publicValues, proof);
    }

    function testRecordRemotePolicyProof() public {
        record.record(publicValues, proof);
    }

    function testRecordRejectsChangedValues() public {
        bytes memory changed = publicValues;
        changed[changed.length / 2] ^= 0x01;
        (bool ok,) = address(record).call(abi.encodeCall(record.record, (changed, proof)));
        require(!ok, "substituted record accepted");
    }

    function testRecordRejectsTrailingProofBytes() public {
        (bool ok,) = address(record).call(abi.encodeCall(record.record, (publicValues, bytes.concat(proof, hex"00"))));
        require(!ok, "noncanonical packet accepted");
    }

    function rejected(bytes32 key, bytes memory values, bytes memory packet) internal view {
        (bool ok,) =
            address(verifier).staticcall{gas: 1_000_000}(abi.encodeCall(verifier.verifyProof, (key, values, packet)));
        require(!ok, "substituted statement accepted");
    }

    function testRejectWrongProgram() public view {
        rejected(program ^ bytes32(uint256(1)), publicValues, proof);
    }

    function testRejectChangedPublicValues() public view {
        bytes memory changed = publicValues;
        changed[changed.length / 2] ^= 0x01;
        rejected(program, changed, proof);
    }

    function testRejectChangedProof() public view {
        bytes memory changed = proof;
        changed[4] ^= 0x01;
        rejected(program, publicValues, changed);
    }

    function testRejectWrongCircuitSelector() public view {
        bytes memory changed = proof;
        changed[0] ^= 0x01;
        rejected(program, publicValues, changed);
    }

    function testRejectTruncatedProof() public view {
        bytes memory truncated = new bytes(259);
        for (uint256 i; i < truncated.length; ++i) {
            truncated[i] = proof[i];
        }
        rejected(program, publicValues, truncated);
    }
}
