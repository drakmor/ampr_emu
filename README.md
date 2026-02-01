NOTE: This is still a POC, not a working solution.

Pure userland implementation of `sce::Ampr` API (AMM + APR) with:
- controllable file I/O backend
- high throughput via batching and concurrency
- no kernel queues/modules (only normal POSIX syscalls)
