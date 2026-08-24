#ifndef AMPR_PAYLOAD_SDK_SCE_PTHREAD_H
#define AMPR_PAYLOAD_SDK_SCE_PTHREAD_H

#include <pthread.h>
#include <stddef.h>
#include "_types.h"

typedef pthread_attr_t ScePthreadAttr;
typedef pthread_condattr_t ScePthreadCondattr;
typedef pthread_cond_t ScePthreadCond;
typedef pthread_t ScePthread;
typedef pthread_mutex_t ScePthreadMutex;
typedef pthread_mutexattr_t ScePthreadMutexattr;
typedef pthread_once_t ScePthreadOnce;

#define SCE_PTHREAD_ONCE_INIT { 0, NULL }
#define SCE_PTHREAD_MUTEX_RECURSIVE 2

#ifdef __cplusplus
extern "C" {
#endif

int scePthreadCondBroadcast(ScePthreadCond *cond);
int scePthreadCondDestroy(ScePthreadCond *cond);
int scePthreadCondInit(ScePthreadCond *cond, const ScePthreadCondattr *attr,
                       const char *name);
int scePthreadCondSignal(ScePthreadCond *cond);
int scePthreadCondTimedwait(ScePthreadCond *cond, ScePthreadMutex *mutex,
                            SceKernelUseconds usec);
int scePthreadCondWait(ScePthreadCond *cond, ScePthreadMutex *mutex);
int scePthreadCreate(ScePthread *thread, const ScePthreadAttr *attr,
                     void *(*entry)(void *), void *arg, const char *name);
int scePthreadGetprio(ScePthread thread, int *prio);
int scePthreadJoin(ScePthread thread, void **value);
int scePthreadMutexattrDestroy(ScePthreadMutexattr *attr);
int scePthreadMutexattrInit(ScePthreadMutexattr *attr);
int scePthreadMutexattrSettype(ScePthreadMutexattr *attr, int type);
int scePthreadMutexDestroy(ScePthreadMutex *mutex);
int scePthreadMutexInit(ScePthreadMutex *mutex,
                        const ScePthreadMutexattr *attr, const char *name);
int scePthreadMutexLock(ScePthreadMutex *mutex);
int scePthreadMutexTrylock(ScePthreadMutex *mutex);
int scePthreadMutexUnlock(ScePthreadMutex *mutex);
int scePthreadOnce(ScePthreadOnce *once, void (*init)(void));
int scePthreadRename(ScePthread thread, const char *name);
ScePthread scePthreadSelf(void);
int scePthreadSetaffinity(ScePthread thread, SceKernelCpumask mask);
int scePthreadSetprio(ScePthread thread, int prio);

#ifdef __cplusplus
}
#endif

#endif
