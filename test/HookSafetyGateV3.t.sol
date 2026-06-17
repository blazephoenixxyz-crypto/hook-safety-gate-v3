// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {HookSafetyGateV3} from "../src/HookSafetyGateV3.sol";

contract BenignHookCode {
    function ping() external pure returns (uint256) { return 1; }
}

contract MaliciousHookCode {
    function ping() external pure returns (uint256) { return 666; }
    function steal() external pure returns (bool) { return true; }
}

contract HookSafetyGateV3Test is Test {
    HookSafetyGateV3 internal gate;

    address internal owner = address(0xA11CE);
    address internal stranger = address(0xBEEF);

    uint160 internal constant BEFORE_SWAP_RETURNS_DELTA_FLAG = uint160(1 << 3);
    uint160 internal constant AFTER_SWAP_RETURNS_DELTA_FLAG = uint160(1 << 2);

    uint256 internal constant DELAY = 2 days;

    uint160 internal constant BASE = uint160(0xaBCd) << 16;

    function _hookWith(uint160 flagBits) internal pure returns (address) {
        return address(BASE | flagBits);
    }

    function _cleanHook() internal pure returns (address) {
        return _hookWith(0);
    }

    function _deltaHook() internal pure returns (address) {
        return _hookWith(BEFORE_SWAP_RETURNS_DELTA_FLAG);
    }

    function setUp() public {
        vm.prank(owner);
        gate = new HookSafetyGateV3(owner, DELAY);
    }

    function _deployBenignAt(address where) internal {
        BenignHookCode c = new BenignHookCode();
        vm.etch(where, address(c).code);
    }

    function _deployMaliciousAt(address where) internal {
        MaliciousHookCode c = new MaliciousHookCode();
        vm.etch(where, address(c).code);
    }

    function _maskLocal() internal pure returns (uint160) {
        return BEFORE_SWAP_RETURNS_DELTA_FLAG | AFTER_SWAP_RETURNS_DELTA_FLAG;
    }

    // ----------------------------- constructor / ownership
    function test_constructor_setsOwnerAndDelay() public view {
        assertEq(gate.owner(), owner);
        assertEq(gate.deltaAdmissionDelay(), DELAY);
    }

    function test_constructor_revertsOnZeroOwner() public {
        vm.expectRevert(HookSafetyGateV3.ZeroAddress.selector);
        new HookSafetyGateV3(address(0), DELAY);
    }

    function test_constructor_zeroDelayAllowed() public {
        HookSafetyGateV3 g = new HookSafetyGateV3(owner, 0);
        assertEq(g.deltaAdmissionDelay(), 0);
    }

    // ----------------------------- constants
    function test_constants_matchV4Core() public pure {
        assertEq(BEFORE_SWAP_RETURNS_DELTA_FLAG, uint160(8));
        assertEq(AFTER_SWAP_RETURNS_DELTA_FLAG, uint160(4));
    }

    // ----------------------------- layer 1
    function test_layer1_beforeSwapDelta_isNotClean() public view {
        assertFalse(gate.hasNoDeltaFlags(_hookWith(BEFORE_SWAP_RETURNS_DELTA_FLAG)));
    }

    function test_layer1_afterSwapDelta_isNotClean() public view {
        assertFalse(gate.hasNoDeltaFlags(_hookWith(AFTER_SWAP_RETURNS_DELTA_FLAG)));
    }

    function test_layer1_bothDeltaFlags_isNotClean() public view {
        assertFalse(gate.hasNoDeltaFlags(_hookWith(_maskLocal())));
    }

    function test_layer1_noDeltaFlags_isClean() public view {
        assertTrue(gate.hasNoDeltaFlags(_cleanHook()));
    }

    function test_layer1_zeroAddress_isClean() public view {
        assertTrue(gate.hasNoDeltaFlags(address(0)));
    }

    // ----------------------------- clean admission
    function test_routable_hooklessPool_alwaysRoutable() public view {
        assertTrue(gate.isRoutableHook(address(0)));
    }

    function test_routable_cleanHookNotAllowlisted_isDenied() public {
        address hook = _cleanHook();
        _deployBenignAt(hook);
        assertFalse(gate.isRoutableHook(hook));
    }

    function test_routable_cleanHookAllowlisted_isRoutable() public {
        address hook = _cleanHook();
        _deployBenignAt(hook);
        vm.prank(owner);
        gate.allowHook(hook);
        assertTrue(gate.isRoutableHook(hook));
        assertFalse(gate.isRoutableDeltaHook(hook));
        assertEq(uint8(gate.statusOf(hook)), uint8(HookSafetyGateV3.Status.Clean));
    }

    function test_allowHook_revertsForDeltaFlaggedHook() public {
        address hook = _deltaHook();
        _deployBenignAt(hook);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(HookSafetyGateV3.HookHasDeltaFlags.selector, hook));
        gate.allowHook(hook);
    }

    function test_allowHook_revertsForZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(HookSafetyGateV3.ZeroAddress.selector);
        gate.allowHook(address(0));
    }

    function test_allowHook_revertsForNoCode() public {
        address hook = _cleanHook();
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(HookSafetyGateV3.HookHasNoCode.selector, hook));
        gate.allowHook(hook);
    }

    function test_allowHook_onlyOwner() public {
        address hook = _cleanHook();
        _deployBenignAt(hook);
        vm.prank(stranger);
        vm.expectRevert(HookSafetyGateV3.NotOwner.selector);
        gate.allowHook(hook);
    }

    function test_allowHook_pinsCodeHashAndEmits() public {
        address hook = _cleanHook();
        _deployBenignAt(hook);
        bytes32 expected = hook.codehash;
        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit HookSafetyGateV3.HookAllowed(hook, expected);
        gate.allowHook(hook);
        assertEq(gate.pinnedCodeHash(hook), expected);
    }

    // ----------------------------- layer 3
    function test_layer3_codeChangeAfterAdmission_makesHookUnroutable() public {
        address hook = _cleanHook();
        _deployBenignAt(hook);
        vm.prank(owner);
        gate.allowHook(hook);
        assertTrue(gate.isRoutableHook(hook));
        _deployMaliciousAt(hook);
        assertFalse(gate.isRoutableHook(hook));
        assertTrue(gate.isStale(hook));
    }

    function test_layer3_reAdmitAfterUpgrade_repinsAndRestores() public {
        address hook = _cleanHook();
        _deployBenignAt(hook);
        vm.prank(owner);
        gate.allowHook(hook);
        _deployMaliciousAt(hook);
        assertFalse(gate.isRoutableHook(hook));
        vm.prank(owner);
        gate.allowHook(hook);
        assertTrue(gate.isRoutableHook(hook));
        assertFalse(gate.isStale(hook));
    }

    function test_layer3_isStale_falseForNeverAdmitted() public {
        address hook = _cleanHook();
        _deployBenignAt(hook);
        assertFalse(gate.isStale(hook));
    }

    // ----------------------------- delta admission
    function test_delta_proposeThenConfirm_makesRoutable() public {
        address hook = _deltaHook();
        _deployBenignAt(hook);
        assertFalse(gate.isRoutableHook(hook));
        vm.prank(owner);
        gate.proposeDeltaHook(hook);
        assertFalse(gate.isRoutableHook(hook));
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(
                HookSafetyGateV3.ProposalNotReady.selector, hook, uint64(block.timestamp + DELAY)
            )
        );
        gate.confirmDeltaHook(hook);
        vm.warp(block.timestamp + DELAY);
        vm.prank(owner);
        gate.confirmDeltaHook(hook);
        assertTrue(gate.isRoutableHook(hook));
        assertTrue(gate.isRoutableDeltaHook(hook));
        assertEq(uint8(gate.statusOf(hook)), uint8(HookSafetyGateV3.Status.Delta));
    }

    function test_delta_proposeRevertsForCleanHook() public {
        address hook = _cleanHook();
        _deployBenignAt(hook);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(HookSafetyGateV3.HookLacksDeltaFlags.selector, hook));
        gate.proposeDeltaHook(hook);
    }

    function test_delta_proposeRevertsForNoCode() public {
        address hook = _deltaHook();
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(HookSafetyGateV3.HookHasNoCode.selector, hook));
        gate.proposeDeltaHook(hook);
    }

    function test_delta_proposeRevertsForZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(HookSafetyGateV3.ZeroAddress.selector);
        gate.proposeDeltaHook(address(0));
    }

    function test_delta_confirmRevertsWithoutProposal() public {
        address hook = _deltaHook();
        _deployBenignAt(hook);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(HookSafetyGateV3.NoPendingProposal.selector, hook));
        gate.confirmDeltaHook(hook);
    }

    function test_delta_confirmRevertsIfCodeChangedSinceProposal() public {
        address hook = _deltaHook();
        _deployBenignAt(hook);
        vm.prank(owner);
        gate.proposeDeltaHook(hook);
        vm.warp(block.timestamp + DELAY);
        _deployMaliciousAt(hook);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(HookSafetyGateV3.CodeHashChangedSinceProposal.selector, hook));
        gate.confirmDeltaHook(hook);
        assertFalse(gate.isRoutableHook(hook));
    }

    function test_delta_codeChangeAfterConfirm_makesUnroutable() public {
        address hook = _deltaHook();
        _deployBenignAt(hook);
        vm.prank(owner);
        gate.proposeDeltaHook(hook);
        vm.warp(block.timestamp + DELAY);
        vm.prank(owner);
        gate.confirmDeltaHook(hook);
        assertTrue(gate.isRoutableHook(hook));
        _deployMaliciousAt(hook);
        assertFalse(gate.isRoutableHook(hook));
        assertTrue(gate.isStale(hook));
    }

    function test_delta_cancelProposal() public {
        address hook = _deltaHook();
        _deployBenignAt(hook);
        vm.prank(owner);
        gate.proposeDeltaHook(hook);
        vm.prank(owner);
        gate.cancelDeltaProposal(hook);
        vm.warp(block.timestamp + DELAY);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(HookSafetyGateV3.NoPendingProposal.selector, hook));
        gate.confirmDeltaHook(hook);
    }

    function test_delta_proposeOnlyOwner() public {
        address hook = _deltaHook();
        _deployBenignAt(hook);
        vm.prank(stranger);
        vm.expectRevert(HookSafetyGateV3.NotOwner.selector);
        gate.proposeDeltaHook(hook);
    }

    function test_delta_confirmOnlyOwner() public {
        address hook = _deltaHook();
        _deployBenignAt(hook);
        vm.prank(owner);
        gate.proposeDeltaHook(hook);
        vm.warp(block.timestamp + DELAY);
        vm.prank(stranger);
        vm.expectRevert(HookSafetyGateV3.NotOwner.selector);
        gate.confirmDeltaHook(hook);
    }

    function test_delta_denyAfterConfirm_revokes() public {
        address hook = _deltaHook();
        _deployBenignAt(hook);
        vm.prank(owner);
        gate.proposeDeltaHook(hook);
        vm.warp(block.timestamp + DELAY);
        vm.startPrank(owner);
        gate.confirmDeltaHook(hook);
        assertTrue(gate.isRoutableHook(hook));
        gate.denyHook(hook);
        vm.stopPrank();
        assertFalse(gate.isRoutableHook(hook));
        assertEq(uint8(gate.statusOf(hook)), uint8(HookSafetyGateV3.Status.None));
    }

    function test_delta_isRoutableDeltaHook_falseForCleanAdmission() public {
        address hook = _cleanHook();
        _deployBenignAt(hook);
        vm.prank(owner);
        gate.allowHook(hook);
        assertTrue(gate.isRoutableHook(hook));
        assertFalse(gate.isRoutableDeltaHook(hook));
    }

    // ----------------------------- ownership transfer
    function test_transferOwnership() public {
        vm.prank(owner);
        gate.transferOwnership(stranger);
        assertEq(gate.owner(), stranger);
    }

    function test_transferOwnership_revertsOnZero() public {
        vm.prank(owner);
        vm.expectRevert(HookSafetyGateV3.ZeroAddress.selector);
        gate.transferOwnership(address(0));
    }

    function test_transferOwnership_onlyOwner() public {
        vm.prank(stranger);
        vm.expectRevert(HookSafetyGateV3.NotOwner.selector);
        gate.transferOwnership(stranger);
    }

    // ----------------------------- fuzz (precompile range excluded)
    function testFuzz_deltaFlaggedHookNeverCleanAdmissible(address hook) public {
        vm.assume(uint160(hook) > 0xff);
        uint160 bits = uint160(hook) & _maskLocal();
        if (bits != 0) {
            _deployBenignAt(hook);
            assertFalse(gate.isRoutableHook(hook));
            vm.prank(owner);
            vm.expectRevert(abi.encodeWithSelector(HookSafetyGateV3.HookHasDeltaFlags.selector, hook));
            gate.allowHook(hook);
        }
    }

    function testFuzz_cleanHookNeverDeltaAdmissible(address hook) public {
        vm.assume(uint160(hook) > 0xff);
        uint160 bits = uint160(hook) & _maskLocal();
        if (bits == 0) {
            _deployBenignAt(hook);
            vm.prank(owner);
            vm.expectRevert(abi.encodeWithSelector(HookSafetyGateV3.HookLacksDeltaFlags.selector, hook));
            gate.proposeDeltaHook(hook);
        }
    }

    function testFuzz_unadmittedNeverRoutable(address hook) public view {
        vm.assume(uint160(hook) > 0xff);
        if (hook.code.length == 0) {
            assertFalse(gate.isRoutableHook(hook));
        }
    }
}
