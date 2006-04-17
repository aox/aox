// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "md5.h"

#include "string.h"
#include "buffer.h"
#include "sys.h"


static void swapBytes( char *, int );


/*! \class MD5 md5.h
    Implements the MD5 message-digest algorithm (RFC 1321).

    Based on public-domain code written by Colin Plumb in 1993.
*/

/*! Creates and initialises an empty MD5 object. */

MD5::MD5()
{
    init();
}


/*! Initialises an MD5 context for use. */

void MD5::init()
{
    int i = 0;
    while ( i < 64 )
        in[i++] = 0;

    buf[0] = 0x67452301;
    buf[1] = 0xefcdab89;
    buf[2] = 0x98badcfe;
    buf[3] = 0x10325476;

    bits[0] = 0;
    bits[1] = 0;

    finalised = false;
}


/*! Updates the MD5 context to reflect the concatenation of \a len bytes
    from \a str.
*/

void MD5::add( const char *str, uint len )
{
    register uint32 t;

    /* XXX: Is this the best thing to do? */
    if ( finalised )
        init();

    /* Update bitcount. */
    t = bits[0];
    bits[0] = t + ((uint32) len << 3);
    if ( bits[0] < t )
        bits[1]++;
    bits[1] += len >> 29;

    t = (t >> 3) & 0x3f;

    /* Handle any leading odd-sized chunks. */
    if ( t != 0 ) {
        char *p = in + t;

        t = 64 - t;
        if ( len < t ) {
            memmove( p, str, len );
            return;
        }

        memmove( p, str, t );
        swapBytes( in, 16 );
        transform();

        str += t;
        len -= t;
    }

    /* Process 64-byte chunks. */
    while ( len >= 64 ) {
        memmove( in, str, 64 );
        swapBytes( in, 16 );
        transform();

        str += 64;
        len -= 64;
    }

    /* Save the rest for later. */
    memmove( in, str, len );
}


/*! \overload
    As above, but adds data from the String \a s.
*/

void MD5::add( const String &s )
{
    add( s.data(), s.length() );
}


/*! Returns the 16-byte MD5 hash of the bytes add()ed so far. */

String MD5::hash()
{
    uint count;
    char *p;

    if ( finalised )
        return String( (char *)buf, 16 );

    /* Compute number of bytes mod 64. */
    count = (bits[0] >> 3) & 0x3F;

    /* Set the first char of padding to 0x80. This is safe since there is
       always at least one byte free. */
    p = in + count;
    *p++ = 0x80;

    /* Bytes of padding needed to make 64 bytes. */
    count = 64 - 1 - count;

    /* Pad out to 56 mod 64. */
    if ( count < 8 ) {
        /* Two lots of padding: Pad the first block to 64 bytes. */
        memset( p, 0, count );
        swapBytes( in, 16 );
        transform();

        /* Now fill the next block with 56 bytes. */
        memset( in, 0, 56 );
    } else {
        /* Pad block to 56 bytes. */
        memset(p, 0, count - 8);
    }
    swapBytes( in, 14 );

    /* Append length in bits and transform. */
    ((uint32 *)in)[14] = bits[0];
    ((uint32 *)in)[15] = bits[1];
    transform();
    swapBytes( (char *)buf, 4 );

    finalised = true;
    return String( (char *)buf, 16 );
}


/*! \overload
    Returns the MD5 hash of the String \a s.
*/

String MD5::hash( const String &s )
{
    MD5 ctx;

    ctx.add( s );
    return ctx.hash();
}


/*! \overload
    Returns the MD5 hash of the Buffer \a s.
*/

String MD5::hash( const Buffer &s )
{
    return hash( s.string(s.size()) );
}


/*! Returns the HMAC-MD5 digest of \a secret and \a text as a 32-char
    hex string with lowercase letters. (RFC 2104)
*/

String MD5::HMAC( const String &secret, const String &text )
{
    uint i, len;
    String s, t;
    char kopad[64], kipad[64];

    /* Hash overly long keys. */
    if ( secret.length() > 64 )
        s = MD5::hash( secret );
    else
        s = secret;
    len = s.length();

    /* Prepare padded key blocks: kopad[0..63] = key[0..63]^opad[0..63],
       where key[n >= len] = 0, and opad[0 <= n < 64] = 0x5c. Similarly
       for kipad, where ipad[0 <= n < 64] = 0x36. */

    i = 0;
    while ( i < len ) {
        kipad[i] = s[i] ^0x36;
        kopad[i] = s[i] ^0x5c;
        i++;
    }
    memset( kipad+len, (char)0^0x36, 64-len );
    memset( kopad+len, (char)0^0x5c, 64-len );

    /* Compute HMAC-MD5 digest: MD5( kopad, MD5( kipad, text )) */
    MD5 ih, oh;

    oh.add( (char *)kopad, 64 );
    ih.add( (char *)kipad, 64 );
    ih.add( text );
    oh.add( ih.hash() );

    return oh.hash();
}


/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) \
        ( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/*! Apply the MD5 hash function to the input block. */

void MD5::transform()
{
    register uint32 a, b, c, d;
    uint32 *inw = (uint32 *)in;

    a = buf[0];
    b = buf[1];
    c = buf[2];
    d = buf[3];

    MD5STEP(F1, a, b, c, d, inw[0] + 0xd76aa478, 7);
    MD5STEP(F1, d, a, b, c, inw[1] + 0xe8c7b756, 12);
    MD5STEP(F1, c, d, a, b, inw[2] + 0x242070db, 17);
    MD5STEP(F1, b, c, d, a, inw[3] + 0xc1bdceee, 22);
    MD5STEP(F1, a, b, c, d, inw[4] + 0xf57c0faf, 7);
    MD5STEP(F1, d, a, b, c, inw[5] + 0x4787c62a, 12);
    MD5STEP(F1, c, d, a, b, inw[6] + 0xa8304613, 17);
    MD5STEP(F1, b, c, d, a, inw[7] + 0xfd469501, 22);
    MD5STEP(F1, a, b, c, d, inw[8] + 0x698098d8, 7);
    MD5STEP(F1, d, a, b, c, inw[9] + 0x8b44f7af, 12);
    MD5STEP(F1, c, d, a, b, inw[10] + 0xffff5bb1, 17);
    MD5STEP(F1, b, c, d, a, inw[11] + 0x895cd7be, 22);
    MD5STEP(F1, a, b, c, d, inw[12] + 0x6b901122, 7);
    MD5STEP(F1, d, a, b, c, inw[13] + 0xfd987193, 12);
    MD5STEP(F1, c, d, a, b, inw[14] + 0xa679438e, 17);
    MD5STEP(F1, b, c, d, a, inw[15] + 0x49b40821, 22);

    MD5STEP(F2, a, b, c, d, inw[1] + 0xf61e2562, 5);
    MD5STEP(F2, d, a, b, c, inw[6] + 0xc040b340, 9);
    MD5STEP(F2, c, d, a, b, inw[11] + 0x265e5a51, 14);
    MD5STEP(F2, b, c, d, a, inw[0] + 0xe9b6c7aa, 20);
    MD5STEP(F2, a, b, c, d, inw[5] + 0xd62f105d, 5);
    MD5STEP(F2, d, a, b, c, inw[10] + 0x02441453, 9);
    MD5STEP(F2, c, d, a, b, inw[15] + 0xd8a1e681, 14);
    MD5STEP(F2, b, c, d, a, inw[4] + 0xe7d3fbc8, 20);
    MD5STEP(F2, a, b, c, d, inw[9] + 0x21e1cde6, 5);
    MD5STEP(F2, d, a, b, c, inw[14] + 0xc33707d6, 9);
    MD5STEP(F2, c, d, a, b, inw[3] + 0xf4d50d87, 14);
    MD5STEP(F2, b, c, d, a, inw[8] + 0x455a14ed, 20);
    MD5STEP(F2, a, b, c, d, inw[13] + 0xa9e3e905, 5);
    MD5STEP(F2, d, a, b, c, inw[2] + 0xfcefa3f8, 9);
    MD5STEP(F2, c, d, a, b, inw[7] + 0x676f02d9, 14);
    MD5STEP(F2, b, c, d, a, inw[12] + 0x8d2a4c8a, 20);

    MD5STEP(F3, a, b, c, d, inw[5] + 0xfffa3942, 4);
    MD5STEP(F3, d, a, b, c, inw[8] + 0x8771f681, 11);
    MD5STEP(F3, c, d, a, b, inw[11] + 0x6d9d6122, 16);
    MD5STEP(F3, b, c, d, a, inw[14] + 0xfde5380c, 23);
    MD5STEP(F3, a, b, c, d, inw[1] + 0xa4beea44, 4);
    MD5STEP(F3, d, a, b, c, inw[4] + 0x4bdecfa9, 11);
    MD5STEP(F3, c, d, a, b, inw[7] + 0xf6bb4b60, 16);
    MD5STEP(F3, b, c, d, a, inw[10] + 0xbebfbc70, 23);
    MD5STEP(F3, a, b, c, d, inw[13] + 0x289b7ec6, 4);
    MD5STEP(F3, d, a, b, c, inw[0] + 0xeaa127fa, 11);
    MD5STEP(F3, c, d, a, b, inw[3] + 0xd4ef3085, 16);
    MD5STEP(F3, b, c, d, a, inw[6] + 0x04881d05, 23);
    MD5STEP(F3, a, b, c, d, inw[9] + 0xd9d4d039, 4);
    MD5STEP(F3, d, a, b, c, inw[12] + 0xe6db99e5, 11);
    MD5STEP(F3, c, d, a, b, inw[15] + 0x1fa27cf8, 16);
    MD5STEP(F3, b, c, d, a, inw[2] + 0xc4ac5665, 23);

    MD5STEP(F4, a, b, c, d, inw[0] + 0xf4292244, 6);
    MD5STEP(F4, d, a, b, c, inw[7] + 0x432aff97, 10);
    MD5STEP(F4, c, d, a, b, inw[14] + 0xab9423a7, 15);
    MD5STEP(F4, b, c, d, a, inw[5] + 0xfc93a039, 21);
    MD5STEP(F4, a, b, c, d, inw[12] + 0x655b59c3, 6);
    MD5STEP(F4, d, a, b, c, inw[3] + 0x8f0ccc92, 10);
    MD5STEP(F4, c, d, a, b, inw[10] + 0xffeff47d, 15);
    MD5STEP(F4, b, c, d, a, inw[1] + 0x85845dd1, 21);
    MD5STEP(F4, a, b, c, d, inw[8] + 0x6fa87e4f, 6);
    MD5STEP(F4, d, a, b, c, inw[15] + 0xfe2ce6e0, 10);
    MD5STEP(F4, c, d, a, b, inw[6] + 0xa3014314, 15);
    MD5STEP(F4, b, c, d, a, inw[13] + 0x4e0811a1, 21);
    MD5STEP(F4, a, b, c, d, inw[4] + 0xf7537e82, 6);
    MD5STEP(F4, d, a, b, c, inw[11] + 0xbd3af235, 10);
    MD5STEP(F4, c, d, a, b, inw[2] + 0x2ad7d2bb, 15);
    MD5STEP(F4, b, c, d, a, inw[9] + 0xeb86d391, 21);

    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}


/* Swap bytes (for big-endian systems). */

static void swapBytes( char *buf, int n )
{
    uint32 t;

    /* This function is harmless on little-endian machines, and required
       on big-endian ones, so we run it anyway. */

    do {
        t = (uint32)((unsigned) buf[3] << 8 | buf[2]) << 16 |
                    ((unsigned) buf[1] << 8 | buf[0]);
        *(uint32 *)buf = t;
        buf += 4;
    }
    while ( --n > 0 );
}


