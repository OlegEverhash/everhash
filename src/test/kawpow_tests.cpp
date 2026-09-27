// Copyright (c) 2019 Veil developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <test/test_raven.h>

#include <boost/test/unit_test.hpp>

#include <crypto/ethash/lib/ethash/endianness.hpp>
#include <crypto/ethash/include/ethash/progpow.hpp>

#include "crypto/ethash/helpers.hpp"
#include "crypto/ethash/progpow_test_vectors.hpp"

#include <array>

BOOST_FIXTURE_TEST_SUITE(kawpow_tests, BasicTestingSetup)
BOOST_AUTO_TEST_CASE(kawpow_l1_cache)
{
    auto& context = get_ethash_epoch_context_0();
    constexpr auto test_size = 20;
    std::array<uint32_t, test_size> cache_slice;
    for (size_t i = 0; i < cache_slice.size(); ++i)
        cache_slice[i] = ethash::le::uint32(context.l1_cache[i]);
    const std::array<uint32_t, test_size> expected{
        {3373657959, 962551522, 1789454947, 4060733492, 319701226, 3605521233,
         1009683087, 1859381145, 1358499679, 791300923, 2286594602, 3399722386,
         2922967251, 4282097249, 1429107374, 711265034, 412375109, 4072788331,
         1465703211, 314691876}};
    int i = 0;
    for (auto item : cache_slice) {
        BOOST_CHECK_EQUAL(item, expected[i]);
        i++;
    }
}

BOOST_AUTO_TEST_CASE(kawpow_hash_empty)
{
    auto& context = get_ethash_epoch_context_0();

    int count = 1000;
    ethash_result result;
    while (count > 0) {
        result = progpow::hash(context, count, {}, 0);
        --count;
    }

    const auto mix_hex = "16ce93d76ac9aab5c61069afed2fae692e5b85ce7020f220a5698f8d93dd25ab";
    const auto final_hex = "cedb8c57847e796c34c1996546801651bd0bfce957fa2dd19db3aad767fc0065";
    BOOST_CHECK_EQUAL(to_hex(result.mix_hash), mix_hex);
    BOOST_CHECK_EQUAL(to_hex(result.final_hash), final_hex);
}

BOOST_AUTO_TEST_CASE(kawpow_hash_30000)
{
    const int block_number = 30000;
    const auto header =
            to_hash256("ffeeddccbbaa9988776655443322110000112233445566778899aabbccddeeff");
    const uint64_t nonce = 0x123456789abcdef0;

    auto context = ethash::create_epoch_context(ethash::get_epoch_number(block_number));

    const auto result = progpow::hash(*context, block_number, header, nonce);
    const auto mix_hex = "87531e1aae54c09a8b3fe8acbd9997646eefd00072d7ce47df299bb8c21aeeea";
    const auto final_hex = "9279978d3aa5dc1c73c28a7ee6da7debb74d82d4f96ba68084bc1882592f0514";
    BOOST_CHECK_EQUAL(to_hex(result.mix_hash), mix_hex);
    BOOST_CHECK_EQUAL(to_hex(result.final_hash), final_hex);

}

BOOST_AUTO_TEST_CASE(kawpow_hash_and_verify)
{
    ethash::epoch_context_ptr context{nullptr, nullptr};

    for (auto& t : progpow_hash_test_cases)
    {
        const auto epoch_number = ethash::get_epoch_number(t.block_number);
        if (!context || context->epoch_number != epoch_number)
            context = ethash::create_epoch_context(epoch_number);

        const auto header_hash = to_hash256(t.header_hash_hex);
        const auto nonce = std::stoull(t.nonce_hex, nullptr, 16);
        const auto result = progpow::hash(*context, t.block_number, header_hash, nonce);
        BOOST_CHECK_EQUAL(to_hex(result.mix_hash), t.mix_hash_hex);
        BOOST_CHECK_EQUAL(to_hex(result.final_hash), t.final_hash_hex);

        auto success = progpow::verify(
                *context, t.block_number, header_hash, result.mix_hash, nonce, result.final_hash);
        BOOST_CHECK(success);

        auto lower_boundary = result.final_hash;
        for (int b = 31; b >= 0; --b) { if (lower_boundary.bytes[b] > 0) { --lower_boundary.bytes[b]; break; } else { lower_boundary.bytes[b] = 0xFF; } }
        auto final_failure = progpow::verify(
                *context, t.block_number, header_hash, result.mix_hash, nonce, lower_boundary);
        BOOST_CHECK(!final_failure);

        auto different_mix = result.mix_hash;
        ++different_mix.bytes[7];
        auto mix_failure = progpow::verify(
                *context, t.block_number, header_hash, different_mix, nonce, result.final_hash);
        BOOST_CHECK(!mix_failure);
    }
}

BOOST_AUTO_TEST_CASE(kawpow_search)
{
    auto ctxp = ethash::create_epoch_context_full(0);
    auto& ctx = *ctxp;
    auto& ctxl = reinterpret_cast<const ethash::epoch_context&>(ctx);
    auto boundary = to_hash256("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    auto sr = progpow::search(ctx, 0, {}, boundary, 0, 200);
    auto srl = progpow::search_light(ctxl, 0, {}, boundary, 0, 200);
    BOOST_CHECK(sr.mix_hash != ethash::hash256{});
    BOOST_CHECK(sr.final_hash != ethash::hash256{});
    BOOST_CHECK(sr.nonce == 98);
    BOOST_CHECK(sr.mix_hash == srl.mix_hash);
    BOOST_CHECK(sr.final_hash == srl.final_hash);
    BOOST_CHECK(sr.nonce == srl.nonce);
    // Search a different nonce range and find another solution
    sr = progpow::search(ctx, 0, {}, boundary, 200, 5000);
    srl = progpow::search_light(ctxl, 0, {}, boundary, 200, 5000);
    BOOST_CHECK(sr.mix_hash != ethash::hash256{});
    BOOST_CHECK(sr.final_hash != ethash::hash256{});
    BOOST_CHECK(sr.nonce == 820);
    BOOST_CHECK(sr.mix_hash == srl.mix_hash);
    BOOST_CHECK(sr.final_hash == srl.final_hash);
    BOOST_CHECK(sr.nonce == srl.nonce);
    auto r = progpow::hash(ctx, 0, {}, 820);
    BOOST_CHECK(sr.final_hash == r.final_hash);
    BOOST_CHECK(sr.mix_hash == r.mix_hash);
}
BOOST_AUTO_TEST_SUITE_END()