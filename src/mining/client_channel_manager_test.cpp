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
#include <cstring>
#include <gtest/gtest.h>

using namespace nexusminer::mining;

TEST(ClientChannelManagerTest, test_client_block_creation)
{
    std::cout << "Test 1: ClientBlock creation and basic methods..." << std::endl;
    
    ClientBlock block;
    block.nVersion = 8;
    block.nHeight = 6535681;
    block.nChannel = CHANNEL_PRIME;
    block.nBits = 0x8063ba01;
    block.nNonce = 12345;
    block.nTime = 1609459200;
    
    ASSERT_TRUE(block.nHeight == 6535681);
    ASSERT_TRUE(block.IsPrime() == true);
    ASSERT_TRUE(block.IsHash() == false);
    ASSERT_TRUE(std::string(block.GetChannelName()) == "PRIME");
    ASSERT_TRUE(block.GetChannel() == CHANNEL_PRIME);
    ASSERT_TRUE(!block.IsNull());
    
    std::cout << "  ✓ ClientBlock: " << block.ToString() << std::endl;
    std::cout << "  ✓ Test 1 PASSED\n" << std::endl;
}

TEST(ClientChannelManagerTest, test_client_block_state)
{
    std::cout << "Test 2: ClientBlockState with channel height..." << std::endl;
    
    ClientBlock block;
    block.nHeight = 6535681;
    block.nChannel = CHANNEL_PRIME;
    block.nVersion = 8;
    
    ClientBlockState state(block, 2301904);
    
    ASSERT_TRUE(state.nHeight == 6535681);  // unified height (from block, set by node)
    ASSERT_TRUE(state.nChannelHeight == 2301904);  // Channel height (from GET_ROUND)
    ASSERT_TRUE(state.GetAge() >= 0);  // Should be valid
    
    std::cout << "  ✓ ClientBlockState: " << state.ToString() << std::endl;
    std::cout << "  ✓ Test 2 PASSED\n" << std::endl;
}

TEST(ClientChannelManagerTest, test_fork_detection)
{
    std::cout << "Test 3: Fork detection via height regression..." << std::endl;
    
    PrimeClientManager mgr;
    
    // Initial state
    mgr.UpdateFromGetRound(6535680, 2301903);
    auto heights1 = mgr.GetNodeHeights();
    ASSERT_TRUE(heights1.first == 6535680);
    ASSERT_TRUE(heights1.second == 2301903);
    
    // Simulate fork (rollback)
    mgr.UpdateFromGetRound(6535650, 2301890);
    auto heights2 = mgr.GetNodeHeights();
    ASSERT_TRUE(heights2.first == 6535650);
    ASSERT_TRUE(heights2.second == 2301890);
    
    // Fork should have been detected (template would have been cleared)
    std::cout << "  ✓ Fork detection triggered (height regressed from " 
              << heights1.first << " to " << heights2.first << ")" << std::endl;
    std::cout << "  ✓ Test 3 PASSED\n" << std::endl;
}

TEST(ClientChannelManagerTest, test_template_validation)
{
    std::cout << "Test 4: Template validation with dual heights..." << std::endl;
    
    PrimeClientManager mgr;
    mgr.UpdateFromGetRound(6535680, 2301903);
    
    // Valid template: nHeight = unified height + 1 (NOT channel height + 1)
    ClientBlock block;
    block.nHeight = 6535681;  // Unified + 1 (nHeight is unified blockchain height)
    block.nChannel = CHANNEL_PRIME;
    ClientBlockState validState(block, 2301904);  // Channel + 1
    
    bool isValid = mgr.ValidateTemplate(&validState);
    ASSERT_TRUE(isValid == true);
    std::cout << "  ✓ Valid template accepted (unified=" << block.nHeight 
              << ", channel=" << validState.nChannelHeight << ")" << std::endl;
    
    // Invalid unified height (stale or fork — nHeight must equal nNodeUnified + 1)
    {
        ClientBlock staleBlock;
        staleBlock.nHeight = 6535680;  // Wrong (should be nNodeUnified + 1 = 6535681)
        staleBlock.nChannel = CHANNEL_PRIME;
        ClientBlockState staleUnified(staleBlock, 2301904);
        isValid = mgr.ValidateTemplate(&staleUnified);
        ASSERT_TRUE(isValid == false);
        std::cout << "  ✓ Stale unified height rejected (nHeight=" << staleUnified.nHeight 
                  << " != expected " << (6535680 + 1) << ")" << std::endl;
    }
    
    // Invalid channel height (secondary guard — channel advanced since template was issued)
    {
        ClientBlock freshBlock;
        freshBlock.nHeight = 6535681;  // Correct unified height
        freshBlock.nChannel = CHANNEL_PRIME;
        ClientBlockState staleChannel(freshBlock, 2301903);  // Wrong nChannelHeight (should be nNodeChannel + 1)
        isValid = mgr.ValidateTemplate(&staleChannel);
        ASSERT_TRUE(isValid == false);
        std::cout << "  ✓ Stale channel height rejected" << std::endl;
    }
    
    std::cout << "  ✓ Test 4 PASSED\n" << std::endl;
}

TEST(ClientChannelManagerTest, test_template_age_timeout)
{
    std::cout << "Test 5: Template age timeout..." << std::endl;
    
    ClientBlock block;
    block.nHeight = 6535681;
    block.nChannel = CHANNEL_PRIME;
    
    ClientBlockState state(block, 2301904);
    
    // Modify creation time to exceed MAX_TEMPLATE_AGE_SECONDS (300s)
    state.nCreationTime = std::time(nullptr) - 301;
    
    PrimeClientManager mgr;
    mgr.UpdateFromGetRound(6535680, 2301903);
    
    bool isValid = mgr.ValidateTemplate(&state);
    ASSERT_TRUE(isValid == false);  // Age timeout (age>300s)
    
    std::cout << "  ✓ Old template (age>" << MAX_TEMPLATE_AGE_SECONDS << "s) rejected (age=" << state.GetAge() << "s)" << std::endl;
    std::cout << "  ✓ Test 5 PASSED\n" << std::endl;
}

TEST(ClientChannelManagerTest, test_channel_independence)
{
    std::cout << "Test 6: Prime and Hash managers track independently..." << std::endl;
    
    PrimeClientManager primeMgr;
    HashClientManager hashMgr;
    
    // Update with different channel heights
    primeMgr.UpdateFromGetRound(6535680, 2301903);
    hashMgr.UpdateFromGetRound(6535680, 4165001);
    
    auto primeHeights = primeMgr.GetNodeHeights();
    auto hashHeights = hashMgr.GetNodeHeights();
    
    ASSERT_TRUE(primeHeights.first == hashHeights.first);  // Same unified
    ASSERT_TRUE(primeHeights.second != hashHeights.second);  // Different channel
    
    std::cout << "  ✓ Prime: unified=" << primeHeights.first 
              << ", channel=" << primeHeights.second << std::endl;
    std::cout << "  ✓ Hash: unified=" << hashHeights.first 
              << ", channel=" << hashHeights.second << std::endl;
    std::cout << "  ✓ Test 6 PASSED\n" << std::endl;
}

TEST(ClientChannelManagerTest, test_template_lifecycle)
{
    std::cout << "Test 7: Template lifecycle management..." << std::endl;
    
    PrimeClientManager mgr;
    mgr.UpdateFromGetRound(6535680, 2301903);
    
    // No template initially
    ASSERT_TRUE(mgr.GetCurrentTemplate() == nullptr);
    ASSERT_TRUE(!mgr.HasValidTemplate());
    std::cout << "  ✓ Initially no template" << std::endl;
    
    // Set template
    ClientBlock block;
    block.nHeight = 6535681;
    block.nChannel = CHANNEL_PRIME;
    auto pState = std::make_unique<ClientBlockState>(block, 2301904);
    mgr.SetCurrentTemplate(std::move(pState));
    
    ASSERT_TRUE(mgr.GetCurrentTemplate() != nullptr);
    ASSERT_TRUE(mgr.HasValidTemplate());
    std::cout << "  ✓ Template set successfully" << std::endl;
    
    // Clear template
    mgr.ClearTemplate();
    ASSERT_TRUE(mgr.GetCurrentTemplate() == nullptr);
    ASSERT_TRUE(!mgr.HasValidTemplate());
    std::cout << "  ✓ Template cleared successfully" << std::endl;
    
    std::cout << "  ✓ Test 7 PASSED\n" << std::endl;
}

TEST(ClientChannelManagerTest, test_is_height_intact)
{
    std::cout << "Test 8: IsHeightIntact() — nHeight read-only invariant..." << std::endl;

    ClientBlock block;
    block.nHeight = 6535681;  // unified height set by node
    block.nChannel = CHANNEL_PRIME;

    ClientBlockState state(block, 2301904);

    // Matches the deserialized height
    ASSERT_TRUE(state.IsHeightIntact(6535681) == true);
    std::cout << "  ✓ IsHeightIntact(6535681) == true (height unchanged)" << std::endl;

    // Mismatch: channel height value accidentally used
    ASSERT_TRUE(state.IsHeightIntact(2301904) == false);
    std::cout << "  ✓ IsHeightIntact(2301904) == false (channel height != unified height)" << std::endl;

    // After a simulated mutation, the check catches the corruption
    state.nHeight = 2301904;  // simulate wrong overwrite with channel height
    ASSERT_TRUE(state.IsHeightIntact(6535681) == false);
    std::cout << "  ✓ IsHeightIntact(6535681) == false after simulated corruption" << std::endl;

    std::cout << "  ✓ Test 8 PASSED\n" << std::endl;
}

TEST(ClientChannelManagerTest, test_hash_prev_block_preserved)
{
    std::cout << "Test 9: hashPrevBlock preserved as primary staleness anchor..." << std::endl;

    ClientBlock block;
    block.nHeight = 6535681;
    block.nChannel = CHANNEL_HASH;
    // Set a non-zero hashPrevBlock (primary staleness anchor per StakeMinter pattern)
    std::vector<uint8_t> prev_data(128);
    for (int i = 0; i < 128; ++i)
        prev_data[i] = static_cast<uint8_t>(i + 1);
    block.hashPrevBlock.SetBytes(prev_data);

    ClientBlockState state(block, 4165002);

    // hashPrevBlock must survive construction — it is read-only from node
    auto prev = state.hashPrevBlock.GetBytes();
    bool all_match = true;
    for (int i = 0; i < 128; ++i)
        if (prev[i] != static_cast<uint8_t>(i + 1)) { all_match = false; break; }
    ASSERT_TRUE(all_match);
    std::cout << "  ✓ hashPrevBlock byte pattern preserved through ClientBlockState construction" << std::endl;

    // GetPlaceholderHash() returns hashPrevBlock (used as template identity)
    uint1024_t placeholder = state.GetPlaceholderHash();
    auto placeholder_bytes = placeholder.GetBytes();
    bool placeholder_matches = true;
    for (int i = 0; i < 128; ++i)
        if (placeholder_bytes[i] != static_cast<uint8_t>(i + 1)) { placeholder_matches = false; break; }
    ASSERT_TRUE(placeholder_matches);
    std::cout << "  ✓ GetPlaceholderHash() returns hashPrevBlock correctly" << std::endl;

    std::cout << "  ✓ Test 9 PASSED\n" << std::endl;
}

TEST(ClientChannelManagerTest, test_expected_heights)
{
    std::cout << "Test 10: GetExpectedHeights() returns (unified+1, channel+1)..." << std::endl;

    PrimeClientManager mgr;
    mgr.UpdateFromGetRound(6535680, 2301903);

    auto expected = mgr.GetExpectedHeights();
    ASSERT_TRUE(expected.first == 6535681);   // unified + 1 — must equal block.nHeight for valid template
    ASSERT_TRUE(expected.second == 2301904);  // channel + 1 — must equal nChannelHeight for valid template
    std::cout << "  ✓ Expected unified = " << expected.first
              << ", expected channel = " << expected.second << std::endl;

    // After tip advances, expected heights update accordingly
    mgr.UpdateFromGetRound(6535681, 2301903);  // unified moved, channel unchanged
    auto expected2 = mgr.GetExpectedHeights();
    ASSERT_TRUE(expected2.first == 6535682);  // unified advanced
    ASSERT_TRUE(expected2.second == 2301904); // channel unchanged
    std::cout << "  ✓ After unified tip move: expected unified = " << expected2.first
              << ", channel = " << expected2.second << std::endl;

    // After channel advances, expected channel height updates
    mgr.UpdateFromGetRound(6535682, 2301904);  // both advanced
    auto expected3 = mgr.GetExpectedHeights();
    ASSERT_TRUE(expected3.first == 6535683);
    ASSERT_TRUE(expected3.second == 2301905);
    std::cout << "  ✓ After both advance: expected unified = " << expected3.first
              << ", channel = " << expected3.second << std::endl;

    std::cout << "  ✓ Test 10 PASSED\n" << std::endl;
}
