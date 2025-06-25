/* Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved. */

#ifndef AREION_PRIVATE_H
#define AREION_PRIVATE_H

#include "areion-const.h"

#if defined(__x86_64__)
#include "areion-aesni.h"
#elif defined(__aarch64__)
#include "areion-neon.h"
#endif

#endif
