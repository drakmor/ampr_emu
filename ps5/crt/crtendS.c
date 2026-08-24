/* Repository PRX crtendS source. */

typedef unsigned long crt_size_t;
typedef void (*crt_func_t)(void);
typedef int (*crt_module_func_t)(crt_size_t, const void *);

extern int module_start(crt_size_t, const void *) __attribute__((weak));
extern crt_func_t __start__Zpreinit_array[];
extern crt_func_t __stop__Zpreinit_array[];
extern crt_func_t __CTOR_LIST__[];
extern crt_func_t __CTOR_END__[];

__attribute__((used, section(".dtors")))
static crt_func_t dtor_end_marker;

__attribute__((used, section(".ctors")))
static crt_func_t ctor_end_marker;

__attribute__((visibility("hidden"), used, section(".init")))
int _init(crt_size_t args, const void *argp, crt_module_func_t override)
{
    for (crt_func_t *entry = __start__Zpreinit_array;
         entry < __stop__Zpreinit_array;
         ++entry) {
        if (*entry) {
            (*entry)();
        }
    }

    for (crt_func_t *entry = __CTOR_END__; entry > __CTOR_LIST__;) {
        crt_func_t constructor = *--entry;
        if (constructor && constructor != (crt_func_t)-1) {
            constructor();
        }
    }

    if (override) {
        return override(args, argp);
    }
    return module_start ? module_start(args, argp) : 0;
}

__asm__(
    ".hidden _init\n"
    ".pushsection .sceversion,\"\",@progbits\n"
    ".byte 0x00,0x00,0x19,0x00,0x08,0x63,0x72,0x74,0x65,0x6e,0x64,0x53,0x3a,0x02,0x00,0x00\n"
    ".byte 0x09,0x00,0x00,0x00,0x01,0x02,0x00,0x00,0x09,0x00,0x00,0x00,0x01\n"
    ".popsection\n"
);
