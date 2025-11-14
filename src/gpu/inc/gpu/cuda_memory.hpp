#ifndef NEXUSMINER_GPU_CUDA_MEMORY_HPP
#define NEXUSMINER_GPU_CUDA_MEMORY_HPP

#include <memory>
#include <cuda_runtime.h>
#include <spdlog/spdlog.h>
#include "gpu_helper.hpp"

namespace nexusminer {
namespace gpu {

/**
 * @brief Custom deleter for CUDA device memory allocated with cudaMalloc
 * Enhanced with error handling and logging for debugging segfaults
 */
struct CudaDeleter {
    void operator()(void* ptr) const {
        if (!ptr) {
            return;  // Nothing to free
        }
        
        try {
            // Get logger if available
            auto logger = spdlog::get("logger");
            
            // Log memory deallocation for debugging
            if (logger) {
                logger->debug("CudaDeleter: Freeing CUDA device memory at {}", ptr);
            }
            
            cudaError_t err = cudaFree(ptr);
            
            if (err != cudaSuccess) {
                // Log the error but don't throw - destructors should be noexcept
                if (logger) {
                    logger->error("CudaDeleter: Failed to free CUDA memory at {}: {} ({})", 
                                  ptr, cudaGetErrorString(err), static_cast<int>(err));
                } else {
                    fprintf(stderr, "CudaDeleter: Failed to free CUDA memory at %p: %s (%d)\n", 
                            ptr, cudaGetErrorString(err), static_cast<int>(err));
                }
            }
        } catch (const std::exception& e) {
            // Catch any exceptions during cleanup to prevent termination
            fprintf(stderr, "CudaDeleter: Exception during CUDA memory cleanup: %s\n", e.what());
        } catch (...) {
            fprintf(stderr, "CudaDeleter: Unknown exception during CUDA memory cleanup\n");
        }
    }
};

/**
 * @brief Custom deleter for CUDA pinned host memory allocated with cudaMallocHost
 * Enhanced with error handling and logging for debugging segfaults
 */
struct CudaHostDeleter {
    void operator()(void* ptr) const {
        if (!ptr) {
            return;  // Nothing to free
        }
        
        try {
            // Get logger if available
            auto logger = spdlog::get("logger");
            
            // Log memory deallocation for debugging
            if (logger) {
                logger->debug("CudaHostDeleter: Freeing CUDA pinned host memory at {}", ptr);
            }
            
            cudaError_t err = cudaFreeHost(ptr);
            
            if (err != cudaSuccess) {
                // Log the error but don't throw - destructors should be noexcept
                if (logger) {
                    logger->error("CudaHostDeleter: Failed to free CUDA host memory at {}: {} ({})", 
                                  ptr, cudaGetErrorString(err), static_cast<int>(err));
                } else {
                    fprintf(stderr, "CudaHostDeleter: Failed to free CUDA host memory at %p: %s (%d)\n", 
                            ptr, cudaGetErrorString(err), static_cast<int>(err));
                }
            }
        } catch (const std::exception& e) {
            // Catch any exceptions during cleanup to prevent termination
            fprintf(stderr, "CudaHostDeleter: Exception during CUDA host memory cleanup: %s\n", e.what());
        } catch (...) {
            fprintf(stderr, "CudaHostDeleter: Unknown exception during CUDA host memory cleanup\n");
        }
    }
};

/**
 * @brief Type alias for unique_ptr with CUDA device memory deleter
 * 
 * Usage:
 *   cuda_unique_ptr<uint32_t> ptr;
 *   uint32_t* raw_ptr = nullptr;
 *   checkGPUErrors(cudaMalloc(&raw_ptr, size * sizeof(uint32_t)));
 *   ptr.reset(raw_ptr);
 */
template<typename T>
using cuda_unique_ptr = std::unique_ptr<T, CudaDeleter>;

/**
 * @brief Type alias for unique_ptr with CUDA pinned host memory deleter
 * 
 * Usage:
 *   cuda_host_unique_ptr<uint64_t> ptr;
 *   uint64_t* raw_ptr = nullptr;
 *   checkGPUErrors(cudaMallocHost(&raw_ptr, size * sizeof(uint64_t)));
 *   ptr.reset(raw_ptr);
 */
template<typename T>
using cuda_host_unique_ptr = std::unique_ptr<T, CudaHostDeleter>;

/**
 * @brief Helper function to allocate CUDA device memory with RAII wrapper
 * 
 * @param count Number of elements to allocate
 * @return cuda_unique_ptr managing the allocated memory
 * @throws cudaError_t on allocation failure
 */
template<typename T>
cuda_unique_ptr<T> make_cuda_unique(size_t count) {
    T* ptr = nullptr;
    cudaError_t err = cudaMalloc(&ptr, count * sizeof(T));
    if (err != cudaSuccess) {
        throw err;
    }
    return cuda_unique_ptr<T>(ptr);
}

/**
 * @brief Helper function to allocate CUDA pinned host memory with RAII wrapper
 * 
 * @param count Number of elements to allocate
 * @return cuda_host_unique_ptr managing the allocated memory
 * @throws cudaError_t on allocation failure
 */
template<typename T>
cuda_host_unique_ptr<T> make_cuda_host_unique(size_t count) {
    T* ptr = nullptr;
    cudaError_t err = cudaMallocHost(&ptr, count * sizeof(T));
    if (err != cudaSuccess) {
        throw err;
    }
    return cuda_host_unique_ptr<T>(ptr);
}

} // namespace gpu
} // namespace nexusminer

#endif // NEXUSMINER_GPU_CUDA_MEMORY_HPP
