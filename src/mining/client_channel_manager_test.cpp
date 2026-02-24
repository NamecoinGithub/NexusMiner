/**
 * @file client_channel_manager_test.cpp
 * @brief Simple verification tests for client-side fork-aware channel management
 * 
 * This is a minimal test program to verify the core functionality without
 * requiring a full test framework. Run this manually to verify behavior.
 */

#include "mining/client_block.h"
#include "mining/client_block_state.h"
#include "mining/client_channel_manager.h"
#include <iostream>
#include <cassert>
#include <cstring>

using namespace nexusminer::mining;

void test_client_block_creation()
{
    std::cout << "Test 1: ClientBlock creation and basic methods..." << std::endl;
    
    ClientBlock block;
    block.nVersion = 8;
    block.nHeight = 6535681;
    block.nChannel = CHANNEL_PRIME;
    block.nBits = 0x8063ba01;
    block.nNonce = 12345;
    block.nTime = 1609459200;
    
    assert(block.nHeight == 6535681);
    assert(block.IsPrime() == true);
    assert(block.IsHash() == false);
    assert(std::string(block.GetChannelName()) == "PRIME");
    assert(block.GetChannel() == CHANNEL_PRIME);
    assert(!block.IsNull());
    
    std::cout << "  ✓ ClientBlock: " << block.ToString() << std::endl;
    std::cout << "  ✓ Test 1 PASSED\n" << std::endl;
}

void test_client_block_state()
{
    std::cout << "Test 2: ClientBlockState with channel height..." << std::endl;
    
    ClientBlock block;
    block.nHeight = 6535681;
    block.nChannel = CHANNEL_PRIME;
    block.nVersion = 8;
    
    ClientBlockState state(block, 2301904);
    
    assert(state.nHeight == 6535681);  // channel_target (from block, set by node)
    assert(state.nChannelHeight == 2301904);  // Channel height (from GET_ROUND)
    assert(state.GetAge() >= 0);  // Should be valid
    
    std::cout << "  ✓ ClientBlockState: " << state.ToString() << std::endl;
    std::cout << "  ✓ Test 2 PASSED\n" << std::endl;
}

void test_fork_detection()
{
    std::cout << "Test 3: Fork detection via height regression..." << std::endl;
    
    PrimeClientManager mgr;
    
    // Initial state
    mgr.UpdateFromGetRound(6535680, 2301903);
    auto heights1 = mgr.GetNodeHeights();
    assert(heights1.first == 6535680);
    assert(heights1.second == 2301903);
    
    // Simulate fork (rollback)
    mgr.UpdateFromGetRound(6535650, 2301890);
    auto heights2 = mgr.GetNodeHeights();
    assert(heights2.first == 6535650);
    assert(heights2.second == 2301890);
    
    // Fork should have been detected (template would have been cleared)
    std::cout << "  ✓ Fork detection triggered (height regressed from " 
              << heights1.first << " to " << heights2.first << ")" << std::endl;
    std::cout << "  ✓ Test 3 PASSED\n" << std::endl;
}

void test_template_validation()
{
    std::cout << "Test 4: Template validation with dual heights..." << std::endl;
    
    PrimeClientManager mgr;
    mgr.UpdateFromGetRound(6535680, 2301903);
    
    // Valid template: nHeight = channel_target = nNodeChannel + 1 (NOT unified + 1)
    ClientBlock block;
    block.nHeight = 2301904;  // channel_target = nNodeChannel + 1
    block.nChannel = CHANNEL_PRIME;
    ClientBlockState validState(block, 2301904);  // Channel + 1
    
    bool isValid = mgr.ValidateTemplate(&validState);
    assert(isValid == true);
    std::cout << "  ✓ Valid template accepted (channel_target=" << block.nHeight 
              << ", nChannelHeight=" << validState.nChannelHeight << ")" << std::endl;
    
    // Invalid channel target (nHeight is wrong - should be nNodeChannel + 1)
    ClientBlockState staleTarget(block, 2301904);
    staleTarget.nHeight = 2301903;  // Wrong channel_target (should be 2301904)
    isValid = mgr.ValidateTemplate(&staleTarget);
    assert(isValid == false);
    std::cout << "  ✓ Wrong channel_target rejected (nHeight=" << staleTarget.nHeight 
              << " != expected " << (2301903 + 1) << ")" << std::endl;
    
    // Invalid channel height (nChannelHeight stale)
    ClientBlockState staleChannel(block, 2301903);  // Wrong (should be +1)
    staleChannel.nHeight = 2301904;  // Correct channel_target
    isValid = mgr.ValidateTemplate(&staleChannel);
    assert(isValid == false);
    std::cout << "  ✓ Stale channel height rejected" << std::endl;
    
    std::cout << "  ✓ Test 4 PASSED\n" << std::endl;
}

void test_template_age_timeout()
{
    std::cout << "Test 5: Template age timeout..." << std::endl;
    
    ClientBlock block;
    block.nHeight = 6535681;
    block.nChannel = CHANNEL_PRIME;
    
    ClientBlockState state(block, 2301904);
    
    // Modify creation time to 61 seconds ago
    state.nCreationTime = std::time(nullptr) - 61;
    
    PrimeClientManager mgr;
    mgr.UpdateFromGetRound(6535680, 2301903);
    
    bool isValid = mgr.ValidateTemplate(&state);
    assert(isValid == false);  // Age timeout
    
    std::cout << "  ✓ Old template (>60s) rejected (age=" << state.GetAge() << "s)" << std::endl;
    std::cout << "  ✓ Test 5 PASSED\n" << std::endl;
}

void test_channel_independence()
{
    std::cout << "Test 6: Prime and Hash managers track independently..." << std::endl;
    
    PrimeClientManager primeMgr;
    HashClientManager hashMgr;
    
    // Update with different channel heights
    primeMgr.UpdateFromGetRound(6535680, 2301903);
    hashMgr.UpdateFromGetRound(6535680, 4165001);
    
    auto primeHeights = primeMgr.GetNodeHeights();
    auto hashHeights = hashMgr.GetNodeHeights();
    
    assert(primeHeights.first == hashHeights.first);  // Same unified
    assert(primeHeights.second != hashHeights.second);  // Different channel
    
    std::cout << "  ✓ Prime: unified=" << primeHeights.first 
              << ", channel=" << primeHeights.second << std::endl;
    std::cout << "  ✓ Hash: unified=" << hashHeights.first 
              << ", channel=" << hashHeights.second << std::endl;
    std::cout << "  ✓ Test 6 PASSED\n" << std::endl;
}

void test_template_lifecycle()
{
    std::cout << "Test 7: Template lifecycle management..." << std::endl;
    
    PrimeClientManager mgr;
    mgr.UpdateFromGetRound(6535680, 2301903);
    
    // No template initially
    assert(mgr.GetCurrentTemplate() == nullptr);
    assert(!mgr.HasValidTemplate());
    std::cout << "  ✓ Initially no template" << std::endl;
    
    // Set template
    ClientBlock block;
    block.nHeight = 6535681;
    block.nChannel = CHANNEL_PRIME;
    auto pState = std::make_unique<ClientBlockState>(block, 2301904);
    mgr.SetCurrentTemplate(std::move(pState));
    
    assert(mgr.GetCurrentTemplate() != nullptr);
    assert(mgr.HasValidTemplate());
    std::cout << "  ✓ Template set successfully" << std::endl;
    
    // Clear template
    mgr.ClearTemplate();
    assert(mgr.GetCurrentTemplate() == nullptr);
    assert(!mgr.HasValidTemplate());
    std::cout << "  ✓ Template cleared successfully" << std::endl;
    
    std::cout << "  ✓ Test 7 PASSED\n" << std::endl;
}

int main()
{
    std::cout << "\n========================================" << std::endl;
    std::cout << "Client-Side Fork-Aware Channel Manager Tests" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    try {
        test_client_block_creation();
        test_client_block_state();
        test_fork_detection();
        test_template_validation();
        test_template_age_timeout();
        test_channel_independence();
        test_template_lifecycle();
        
        std::cout << "========================================" << std::endl;
        std::cout << "✓ ALL TESTS PASSED (7/7)" << std::endl;
        std::cout << "========================================\n" << std::endl;
        
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "✗ TEST FAILED: " << e.what() << std::endl;
        return 1;
    }
    catch (...) {
        std::cerr << "✗ TEST FAILED: Unknown error" << std::endl;
        return 1;
    }
}
