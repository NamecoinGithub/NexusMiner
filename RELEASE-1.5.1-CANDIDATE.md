# NexusMiner 1.5.1 candidate

These artifacts are built from `MINER` commit
`a2898872b026e82d9a00c8facbaaba29f4a702ed`. The release is not published.
Download the candidate artifacts from the Actions run associated with this
branch. Each artifact includes its archive and a SHA-256 checksum.

## Linux x86-64

- `NexusMiner-1.5.1-linux-x86_64-cpu-prime.tar.gz` supports CPU Prime and CPU
  hash. It is not a GPU build.
- `NexusMiner-1.5.1-linux-x86_64-nvidia-cuda-hash-only.tar.gz` supports NVIDIA
  GPU hash and CPU hash, **not Prime mining**. This build is experimental and
  has not been tested with a GPU or a live mining session. Report results,
  GPU model, driver version and relevant logs without disclosing keys.

Both require a compatible x86-64 Linux system with glibc 2.38 or newer,
libstdc++ and OpenSSL 3 (`libcrypto.so.3`). CPU Prime also requires GMP
(`libgmp.so.10`). They were built on Ubuntu 24.04. NVIDIA hash uses CUDA 12.8
and requires a compatible NVIDIA driver and supported GPU; the compiled
architectures are 61, 75, 80, 86, 89 and 90. The CUDA runtime is statically
linked. Host tests and version checks passed, but no live mining was tested.
Verify each archive with its accompanying `SHA256SUMS.txt`.

Extract the archive, choose and edit an appropriate file in `configs/`, and
follow the included README and configuration guide. Keep Falcon private keys
confidential.

## Missing builds

The current NVIDIA Prime code does not compile: `sieve_impl.cu` performs
arithmetic on `std::unique_ptr`. The AMD HIP build reaches a CUDA-only header.
macOS Prime fails on `std::atomic<std::shared_ptr<...>>`, and Windows Prime
fails because `segment_allocator.hpp` uses `std::string` without including its
header. No binaries for these combinations are provided. Do not treat GPU
host stubs or CPU-only builds as GPU releases.

Changes since the prior release include startup/template wait diagnostics,
decoded submission rejections, socket-loss recovery, and GPU Prime sieve and
submission changes. GPU Prime still needs a successful build and hardware
testing.
