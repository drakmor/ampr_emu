/* Repository PRX crtbeginS source. */

typedef unsigned long crt_size_t;
typedef void (*crt_func_t)(void);
typedef int (*crt_module_func_t)(crt_size_t, const void *);

extern int Need_sceLibcInternal;
extern int module_stop(crt_size_t, const void *) __attribute__((weak));
extern void __cxa_finalize(void *) __attribute__((weak));
extern crt_func_t __DTOR_LIST__[];
extern crt_func_t __DTOR_END__[];

__attribute__((visibility("hidden"), used, section(".data.__dso_handle")))
void *__dso_handle = &__dso_handle;

__attribute__((used, section(".data.sceLibcInternal")))
static void *sceLibcInternal = &Need_sceLibcInternal;

__attribute__((used, section(".ctors")))
static crt_func_t ctor_list_marker = (crt_func_t)-1;

__attribute__((used, section(".dtors")))
static crt_func_t dtor_list_marker = (crt_func_t)-1;

__attribute__((used, section(".data._fini.completed")))
static unsigned char fini_completed;

__attribute__((
    visibility("hidden"), used, aligned(8), section(".sce_module_param")
))
const unsigned char _sceModuleParam[32] = {
    0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xbf, 0xf4, 0x13, 0x3c, 0x03, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x05, 0x08, 0x09, 0x00, 0x00, 0x02,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

__attribute__((visibility("hidden"), used, section(".fini")))
int _fini(crt_size_t args, const void *argp, crt_module_func_t override)
{
    int result = 0;
    if (fini_completed) {
        return 0;
    }

    if (override) {
        result = override(args, argp);
    } else if (module_stop) {
        result = module_stop(args, argp);
    }

    if (__cxa_finalize) {
        __cxa_finalize(__dso_handle);
    }

    for (crt_func_t *entry = __DTOR_LIST__ + 1;
         entry < __DTOR_END__ && *entry;
         ++entry) {
        (*entry)();
    }

    fini_completed = 1;
    return result;
}

__asm__(
    ".hidden _fini\n"
    ".hidden __dso_handle\n"
    ".hidden _sceModuleParam\n"
    ".pushsection .sceversion,\"\",@progbits\n"
    ".byte 0x00,0x00,0x1b,0x00,0x08,0x63,0x72,0x74,0x62,0x65,0x67,0x69,0x6e,0x53,0x3a,0x02\n"
    ".byte 0x00,0x00,0x09,0x00,0x00,0x00,0x01,0x02,0x00,0x00,0x09,0x00,0x00,0x00,0x01\n"
    ".popsection\n"
);
