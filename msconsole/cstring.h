// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef CSTRING_H
#define CSTRING_H

#include "string.h"
#undef STRING_H

#if defined(unix)
#include "/usr/include/string.h"
#else
#error "must tweak cstring to this OS"
#endif

#ifndef STRING_H
#define STRING_H
#endif


#endif
