#ifndef TSAN_INTERCEPTORS_H
#define TSAN_INTERCEPTORS_H

#include "sanitizer_common/sanitizer_stacktrace.h"
#include "tsan_rtl.h"

namespace __tsan {

class ScopedInterceptor {
 public:
  ScopedInterceptor(ThreadState *thr, const char *fname, uptr pc);
  ~ScopedInterceptor();
  void DisableIgnores() {
    if (UNLIKELY(ignoring_))
      DisableIgnoresImpl();
  }
  void EnableIgnores() {
    if (UNLIKELY(ignoring_))
      EnableIgnoresImpl();
  }

 private:
  ThreadState *const thr_;
  bool in_ignored_lib_;
  bool ignoring_;

  void DisableIgnoresImpl();
  void EnableIgnoresImpl();
};

LibIgnore *libignore();

#if !SANITIZER_GO
inline bool in_symbolizer() {
  cur_thread_init();
  return UNLIKELY(cur_thread()->in_symbolizer);
}
#endif

ALWAYS_INLINE
ThreadState *cur_thread_init_maybe() {
#  if SANITIZER_LINUX
  // On Linux we always have cur_thread initialized
  // when we reach any interceptor. The main thread
  // is initialized from .preinit_array, and other
  // threads are initialized from _setjmp interceptor
  // called from within pthread guts.
  DCHECK(cur_thread());
  return cur_thread();
#  else
  return cur_thread_init();
#  endif
}

}  // namespace __tsan

#define SCOPED_INTERCEPTOR_RAW(func, ...)            \
  ThreadState* thr = cur_thread_init_maybe();        \
  ScopedInterceptor si(thr, #func, GET_CALLER_PC()); \
  const uptr pc = GET_CURRENT_PC();                  \
  (void)pc;

//!!! we need to calculate in_ignored_lib for _this_ interceptor
#define SCOPED_TSAN_INTERCEPTOR(func, ...)                             \
  ThreadState* thr = cur_thread_init_maybe();                          \
  if (UNLIKELY(REAL(func) == 0)) {                                     \
    Report("FATAL: ThreadSanitizer: failed to intercept %s\n", #func); \
    Die();                                                             \
  }                                                                    \
  if (UNLIKELY(!thr->is_inited || thr->ignore_interceptors ||          \
               thr->in_ignored_lib))                                   \
    return REAL(func)(__VA_ARGS__);                                    \
  ScopedInterceptor si(thr, #func, GET_CALLER_PC());                   \
  const uptr pc = GET_CURRENT_PC();                                    \
  (void)pc;

#define SCOPED_TSAN_INTERCEPTOR_USER_CALLBACK_START() \
    si.DisableIgnores();

#define SCOPED_TSAN_INTERCEPTOR_USER_CALLBACK_END() \
    si.EnableIgnores();

#define TSAN_INTERCEPTOR(ret, func, ...) INTERCEPTOR(ret, func, __VA_ARGS__)

#if SANITIZER_NETBSD
# define TSAN_INTERCEPTOR_NETBSD_ALIAS(ret, func, ...) \
  TSAN_INTERCEPTOR(ret, __libc_##func, __VA_ARGS__) \
  ALIAS(WRAPPER_NAME(pthread_##func));
# define TSAN_INTERCEPTOR_NETBSD_ALIAS_THR(ret, func, ...) \
  TSAN_INTERCEPTOR(ret, __libc_thr_##func, __VA_ARGS__) \
  ALIAS(WRAPPER_NAME(pthread_##func));
# define TSAN_INTERCEPTOR_NETBSD_ALIAS_THR2(ret, func, func2, ...) \
  TSAN_INTERCEPTOR(ret, __libc_thr_##func, __VA_ARGS__) \
  ALIAS(WRAPPER_NAME(pthread_##func2));
#else
# define TSAN_INTERCEPTOR_NETBSD_ALIAS(ret, func, ...)
# define TSAN_INTERCEPTOR_NETBSD_ALIAS_THR(ret, func, ...)
# define TSAN_INTERCEPTOR_NETBSD_ALIAS_THR2(ret, func, func2, ...)
#endif

#endif  // TSAN_INTERCEPTORS_H
