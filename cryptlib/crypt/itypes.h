/*
 -------------------------------------------------------------------------
 Copyright (c) 2001, Dr Brian Gladman <brg@gladman.me.uk>, Worcester, UK.
 All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software in both source and binary 
 form is allowed (with or without changes) provided that:

   1. distributions of this source code include the above copyright 
      notice, this list of conditions and the following disclaimer;

   2. distributions in binary form include the above copyright
      notice, this list of conditions and the following disclaimer
      in the documentation and/or other associated materials;

   3. the copyright holder's name is not used to endorse products 
      built using this software without specific written permission. 

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness 
 and fitness for purpose.
 -------------------------------------------------------------------------
 Issue Date: 16/07/2002

 This file contains code to set the definitions for fixed length signed and
 unsigned integer types.   Many systems now contain headers that define the
 intN_t and uintN_t types where N is 8, 16, 32, 64 and 128.  If your system 
 has such an include file you can use it here but you will also need to set
 the suffixes s_s32, s_u32, s_s64 and s_u64 to those used on your system to
 denote signed and unsigned 32 and 64 bit literal numeric values.
*/

#ifndef _ITYPES_H
#define _ITYPES_H

#include <limits.h>

/*  Defines for suffixes to 32 and 64 bit signed and unsigned numeric values	*/

#define sfx_lo(x,y) x##y
#define sfx_hi(x,y) sfx_lo(x,y)
#define n_s32(p)    sfx_hi(0x##p,s_s32)
#define n_u32(p)    sfx_hi(0x##p,s_u32)
#define n_s64(p)    sfx_hi(0x##p,s_s64)
#define n_u64(p)    sfx_hi(0x##p,s_u64)

#if CHAR_MAX == 0x7f
  typedef char                 int8_t;
#elif SCHAR_MAX == 0x7f
  typedef signed char          int8_t;
#endif

#if UCHAR_MAX == 0xff
  typedef unsigned char       uint8_t;
#endif

#if SHRT_MAX == 0x7fff
  typedef short               int16_t;
#endif

#if USHRT_MAX == 0xffff
  typedef   unsigned short   uint16_t;
#endif

#if INT_MAX == 0x7fffffff
  typedef   int               int32_t;
  #define s_s32   
#elif LONG_MAX == 0x7fffffff
  typedef   long              int32_t;
  #define s_s32    l
#endif

#if UINT_MAX == 0xffffffff
  typedef   unsigned int     uint32_t;
  #define s_u32    u
#elif ULONG_MAX == 0xffffffff
  typedef   unsigned long    uint32_t;
  #define s_u32   ul
#endif

#if LONG_MAX > 0x7fffffff
  typedef long                int64_t;
  #define s_s64    l
#elif defined( _MSC_VER )
  typedef __int64             int64_t;
  #define s_s64  i64
#else
  typedef long long           int64_t;
  #define s_s64   ll
#endif

#if ULONG_MAX > 0xffffffff
  typedef unsigned long      uint64_t;
  #define s_u64   ul
#elif defined( _MSC_VER )
  typedef unsigned __int64   uint64_t;
  #define s_u64 ui64
#else
  typedef unsigned long long uint64_t;
  #define s_u64  ull
#endif

#endif
