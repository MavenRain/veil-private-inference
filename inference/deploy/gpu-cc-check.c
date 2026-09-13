/* NVML ABI: NVIDIA nvmlConfComputeSystemState_t and system/device APIs.
 * Constants and layout: NVIDIA NVML API Reference, Confidential Computing.
 * This local check is trusted only as part of the measured workload image. */
#include <dlfcn.h>
#include <stdio.h>

typedef struct { unsigned int environment, ccFeature, devToolsMode; } CcState;
typedef int (*NoArgs)(void);
typedef int (*StateFn)(CcState *);
typedef int (*UnsignedFn)(unsigned int *);

int main(void) {
    void *library = dlopen("libnvidia-ml.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!library) { fputs("gpu-mode-unavailable\n", stderr); return 1; }
    NoArgs init = (NoArgs)dlsym(library, "nvmlInit_v2");
    NoArgs shutdown = (NoArgs)dlsym(library, "nvmlShutdown");
    StateFn state_fn = (StateFn)dlsym(library, "nvmlSystemGetConfComputeState");
    UnsignedFn count_fn = (UnsignedFn)dlsym(library, "nvmlDeviceGetCount_v2");
    UnsignedFn ready_fn = (UnsignedFn)dlsym(library, "nvmlSystemGetConfComputeGpusReadyState");
    if (!init || !shutdown || !state_fn || !count_fn || !ready_fn || init() != 0) {
        dlclose(library); fputs("gpu-mode-unavailable\n", stderr); return 1;
    }
    CcState state = {0, 0, 0};
    unsigned int count = 0, ready = 0;
    int valid = state_fn(&state) == 0 && count_fn(&count) == 0 && ready_fn(&ready) == 0
        && state.environment == 2 && state.ccFeature == 1 && state.devToolsMode == 0
        && count == 1 && ready == 1;
    int closed = shutdown();
    dlclose(library);
    if (!valid || closed != 0) { fputs("gpu-mode-rejected\n", stderr); return 1; }
    puts("{\"cc\":true,\"debug\":false,\"production\":true,\"ready\":true,\"gpus\":1}");
    return 0;
}
