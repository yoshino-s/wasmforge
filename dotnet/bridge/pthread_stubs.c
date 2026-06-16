// Complete pthread stubs for single-threaded WASM (NativeAOT runtime)
typedef struct { int dummy; } pthread_mutex_t;
typedef struct { int dummy; } pthread_mutexattr_t;
typedef struct { int dummy; } pthread_condattr_t;
typedef struct { int dummy; } pthread_cond_t;

int pthread_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *a) { return 0; }
int pthread_mutex_destroy(pthread_mutex_t *m) { return 0; }
int pthread_mutex_lock(pthread_mutex_t *m) { return 0; }
int pthread_mutex_unlock(pthread_mutex_t *m) { return 0; }
int pthread_mutexattr_init(pthread_mutexattr_t *a) { return 0; }
int pthread_mutexattr_settype(pthread_mutexattr_t *a, int type) { return 0; }
int pthread_mutexattr_destroy(pthread_mutexattr_t *a) { return 0; }
int pthread_condattr_init(pthread_condattr_t *a) { return 0; }
int pthread_condattr_destroy(pthread_condattr_t *a) { return 0; }
int pthread_cond_init(pthread_cond_t *c, const pthread_condattr_t *a) { return 0; }
int pthread_cond_destroy(pthread_cond_t *c) { return 0; }
int pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m) { return 0; }
int pthread_cond_broadcast(pthread_cond_t *c) { return 0; }
int pthread_cond_signal(pthread_cond_t *c) { return 0; }
int pthread_cond_timedwait(pthread_cond_t *c, pthread_mutex_t *m, const void *t) { return 0; }
int pthread_self() { return 1; }
