#if AMPR_PAYLOAD_SDK_BUILD
extern "C" __attribute__((visibility("hidden"))) int Need_sceLibcInternal = 0;
#else
extern "C" __attribute__((visibility("hidden"))) int Need_sceLibc = 0;
#endif
