#ifndef NEXUSMINER_WEAK_PTR_UTILS_HPP
#define NEXUSMINER_WEAK_PTR_UTILS_HPP

namespace nexusminer {
namespace util {

/**
 * @brief Guard macro for the common weak_ptr lock-and-check pattern.
 *
 * Locks a @c std::weak_ptr into a local @c std::shared_ptr named @p name.
 * If the lock fails (the managed object has been destroyed), the enclosing
 * function returns immediately.  An optional return value may be supplied
 * for non-void functions.
 *
 * @note This macro intentionally does NOT use the do { ... } while(0)
 *       idiom because the declared variable @p name must remain in scope
 *       after the macro for subsequent code to use.  Always invoke on its
 *       own statement line with a trailing semicolon.
 *
 * @code
 *   // void function — returns nothing on failure:
 *   LOCK_WEAK_OR_RETURN(weak_self, self);
 *
 *   // non-void function — returns a default-constructed result:
 *   LOCK_WEAK_OR_RETURN(weak_wm, wm, result);
 * @endcode
 *
 * @param weak  The std::weak_ptr to lock.
 * @param name  Name of the resulting std::shared_ptr variable.
 * @param ...   (Optional) value to return when the lock fails.
 */
#define LOCK_WEAK_OR_RETURN(weak, name, ...) \
    auto name = (weak).lock();               \
    if (!(name)) return __VA_ARGS__

} // namespace util
} // namespace nexusminer

#endif // NEXUSMINER_WEAK_PTR_UTILS_HPP
