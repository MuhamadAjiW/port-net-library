#ifndef _BUILD_CONFIG_H
#define _BUILD_CONFIG_H

#define DEBUG_TRACE
// #define DEPLOY_BUILD
// #define CHECK_BUILD

#ifdef CHECK_BUILD
#undef DEPLOY_BUILD
#endif

#endif