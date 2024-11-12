#ifndef _BUILD_CONFIG_H
#define _BUILD_CONFIG_H

// #define DEBUG_TRACE
// #define DISABLE_LOG
// #define CHECK_BUILD
// #ifndef USE_DPDK
// #define USE_DPDK
// #endif

#ifndef DEPLOY_BUILD
#define DEPLOY_BUILD
#endif

#ifdef CHECK_BUILD
#undef DEPLOY_BUILD
#endif

#endif