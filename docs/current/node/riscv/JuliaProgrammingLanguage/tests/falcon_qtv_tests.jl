# =============================================================================
# 🟣 Falcon QTV — Correctness and Parity Tests
# =============================================================================
# Tests for falcon_quantum_tunnel_vector.jl
# All tests use FIXED seeds and FIXED fixture payloads for reproducibility.
# =============================================================================

using Test

include("../crypto/falcon_quantum_tunnel_vector.jl")
using .FalconQuantumTunnelVector

function fixture_privkey()
    return UInt8[UInt8((index * 73 + 19) % 256) for index in 0:(FALCON1024_PRIVKEY_SIZE - 1)]
end

const FIXED_SEED = 0x1024fedc

@testset "Falcon Quantum Tunnel Vector" begin
    privkey = fixture_privkey()

    @testset "partitioning preserves payload" begin
        qtv = build_qtv(privkey; seed = FIXED_SEED)

        @test bucket_lengths(qtv) == [577, 576, 576, 576]
        @test reconstruct_payload(qtv) == privkey
        @test decode_working_vector(qtv) == qtv.buckets[qtv.active_bucket_id].payload
    end

    @testset "seeded permutation and swap log are deterministic" begin
        lhs = build_qtv(privkey; seed = FIXED_SEED)
        rhs = build_qtv(privkey; seed = FIXED_SEED)

        @test lattice_safe_permutation(lhs) == lattice_safe_permutation(rhs)
        @test lhs.working_vector == rhs.working_vector
        @test lhs.swap_log == rhs.swap_log
    end

    @testset "swap cycle remains invertible" begin
        qtv = build_qtv(privkey; seed = FIXED_SEED)

        initial_bucket_id = qtv.active_bucket_id
        swap_bucket!(qtv, 2)
        @test qtv.epoch == 0x01
        @test decode_working_vector(qtv) == qtv.buckets[qtv.active_bucket_id].payload

        swap_bucket!(qtv, 4)
        @test qtv.epoch == 0x02
        @test decode_working_vector(qtv) == qtv.buckets[qtv.active_bucket_id].payload

        swap_bucket!(qtv, 1)
        @test qtv.epoch == 0x03
        @test qtv.active_bucket_id == initial_bucket_id
        @test decode_working_vector(qtv) == qtv.buckets[qtv.active_bucket_id].payload
        @test length(qtv.swap_log) == 4
        @test [event.slot for event in qtv.swap_log] == [1, 2, 4, 1]
    end

    @testset "invalid payload size is rejected" begin
        @test_throws ArgumentError build_qtv(privkey[1:end-1]; seed = FIXED_SEED)
    end
end
