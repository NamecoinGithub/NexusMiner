#ifndef NEXUSMINER_MONOTONIC_VALUE_HPP
#define NEXUSMINER_MONOTONIC_VALUE_HPP

namespace nexusminer {
namespace util {

/**
 * @brief Advance a value monotonically.
 *
 * If @p proposed is strictly greater than @p current, assigns @p proposed
 * to @p current and returns true.  Otherwise @p current is unchanged and
 * the function returns false.
 *
 * Replaces the common pattern:
 *     current = std::max(current, proposed);
 * when the caller also needs to know whether the value actually changed.
 *
 * @tparam T  Any type supporting operator>
 * @param current   The value to (possibly) advance — modified in place.
 * @param proposed  The candidate new value.
 * @return true if @p current was advanced.
 */
template <typename T>
bool monotonic_advance(T& current, T proposed) {
    if (proposed > current) { current = proposed; return true; }
    return false;
}

} // namespace util
} // namespace nexusminer

#endif // NEXUSMINER_MONOTONIC_VALUE_HPP
