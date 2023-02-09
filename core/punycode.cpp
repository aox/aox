// This file is a slight adaption of the sample code in RFC 3492;
// no copyright is claimed.

#include "punycode.h"

#include "ustring.h"

#include <limits.h>
#include <stddef.h>


/*** Bootstring parameters for Punycode ***/

static const uint base = 36;
static const uint tmin = 1;
static const uint tmax = 26;
static const uint skew = 38;
static const uint damp = 700;
static const uint initialBias = 72;
static const uint initialN = 0x80;
static const uint delimiter = 0x2D;

/* basic(cp) tests whether cp is a basic code point: */
static inline bool basic(uint cp) {
    return cp < 0x80;
}

/* delim(cp) tests whether cp is a delimiter: */
static inline bool delim(uint cp) {
    return cp == delimiter;
}

/* decode_digit(cp) returns the numeric value of a basic code point
 (for use in representing integers) in the range 0 to base-1, or base
 if cp does not represent a value.  */

static inline uint decodeDigit(uint cp)
{
  return  cp - 48 < 10 ? cp - 22 :  cp - 65 < 26 ? cp - 65 :
          cp - 97 < 26 ? cp - 97 :  base;
}

/* encode_digit(d,flag) returns the basic code point whose value (when
 used for representing integers) is d, which needs to be in the range
 0 to base-1.  The lowercase form is used unless flag is nonzero, in
 which case the uppercase form is used.  The behavior is undefined if
 flag is nonzero and digit d has no uppercase form. */

static inline char encodeDigit(uint d, int flag)
{
  return d + 22 + 75 * (d < 26) - ((flag != 0) << 5);
  /*  0..25 map to ASCII a..z or A..Z */
  /* 26..35 map to ASCII 0..9         */
}

/* flagged(bcp) tests whether a basic code point is flagged
   (uppercase).  The behavior is undefined if bcp is not a basic code
   point.  */

static inline bool flagged(uint bcp) {
    return bcp - 65 < 26;
}

/* encode_basic(bcp,flag) forces a basic code point to lowercase if
   flag is zero, uppercase if flag is nonzero, and returns the
   resulting code point.  The code point is unchanged if it is
   caseless.  The behavior is undefined if bcp is not a basic code
   point.  */

static inline char encodeBasic(uint bcp, int flag)
{
  bcp -= (bcp - 97 < 26) << 5;
  return bcp + ((!flag && (bcp - 65 < 26)) << 5);
}

/*** Bias adaptation function ***/

static uint adapt(uint delta, uint numpoints, int firsttime )
{
    uint k;

    delta = firsttime ? delta / damp : delta >> 1;
    /* delta >> 1 is a faster way of doing delta / 2 */
    delta += delta / numpoints;

    for (k = 0;  delta > ((base - tmin) * tmax) / 2;  k += base) {
        delta /= base - tmin;
    }

    return k + (base - tmin + 1) * delta / (delta + skew);
}

#if 0
// aox doesn't need encoding, at least not yet, so leave this out, YASGNI
/*** Main encode function ***/

enum punycode_ punycode_encode(
  size_t input_length_orig,
  const punycode_uint input[],
  const unsigned char case_flags[],
  size_t *output_length,
  char output[] )
{
  punycode_uint input_length, n, delta, h, b, bias, j, m, q, k, t;
  size_t out, max_out;

  /* The Punycode spec assumes that the input length is the same type */
  /* of integer as a code point, so we need to convert the size_t to  */
  /* a punycode_uint, which could overflow.                           */

  if (input_length_orig > UINT_MAX) return punycode_overflow;
  input_length = (punycode_uint) input_length_orig;

  /* Initialize the state: */

  n = initial_n;
  delta = 0;
  out = 0;
  max_out = *output_length;
  bias = initial_bias;

  /* Handle the basic code points: */

  for (j = 0;  j < input_length;  ++j) {
    if (basic(input[j])) {
      if (max_out - out < 2) return punycode_big_output;
      output[out++] = case_flags ?
        encode_basic(input[j], case_flags[j]) : (char) input[j];
    }
    /* else if (input[j] < n) return punycode_bad_input; */
    /* (not needed for Punycode with unsigned code points) */
  }

  h = b = (punycode_uint) out;
  /* cannot overflow because out <= input_length <= UINT_MAX */

  /* h is the number of code points that have been handled, b is the  */
  /* number of basic code points, and out is the number of ASCII code */
  /* points that have been output.                                    */

  if (b > 0) output[out++] = delimiter;

  /* Main encoding loop: */

  while (h < input_length) {
    /* All non-basic code points < n have been     */
    /* handled already.  Find the next larger one: */

    for (m = UINT_MAX, j = 0;  j < input_length;  ++j) {
      /* if (basic(input[j])) continue; */
      /* (not needed for Punycode) */
      if (input[j] >= n && input[j] < m) m = input[j];
    }

    /* Increase delta enough to advance the decoder's    */
    /* <n,i> state to <m,0>, but guard against overflow: */

    if (m - n > (UINT_MAX - delta) / (h + 1)) return punycode_overflow;
    delta += (m - n) * (h + 1);
    n = m;

    for (j = 0;  j < input_length;  ++j) {
      /* Punycode does not need to check whether input[j] is basic: */
      if (input[j] < n /* || basic(input[j]) */ ) {
        if (++delta == 0) return punycode_overflow;
      }

      if (input[j] == n) {
        /* Represent delta as a generalized variable-length integer: */

        for (q = delta, k = base;  ;  k += base) {
          if (out >= max_out) return punycode_big_output;
          t = k <= bias /* + tmin */ ? tmin :     /* +tmin not needed */
              k >= bias + tmax ? tmax : k - bias;
          if (q < t) break;
          output[out++] = encode_digit(t + (q - t) % (base - t), 0);
          q = (q - t) / (base - t);
        }

        output[out++] = encode_digit(q, case_flags && case_flags[j]);
        bias = adapt(delta, h + 1, h == b);
        delta = 0;
        ++h;
      }
    }

    ++delta, ++n;
  }

  *output_length = out;
  return punycode_success;
}
#endif

/*! Decodes a punycoded string and returns the result, or its input if
    there's anhy failure. */

UString Punycode::decode(const UString & input) {
    UString result;
    uint n, i, bias, oldi, w, k, digit, t;
    size_t b, j, in;

    /* Initialize the state: */

    n = initialN;
    i = 0;
    bias = initialBias;

    /* Handle the basic code points: Let b be the number of input code
       points before the last delimiter, or 0 if there is none, then
       copy the first b code points to the output.  */

    for ( b = j = 0; j < input.length(); ++j)
        if ( delim(input[j]) )
            b = j;

    for ( j = 0; j < b; ++j ) {
        if ( !basic(input[j]) )
            return UString();
        result.append( input[j] );
    }

    /* Main decoding loop: Start just after the last delimiter if any
       basic code points were copied; start at the beginning
       otherwise. */

    in = b > 0 ? b + 1 : 0;
    while ( in < input.length() ) {

        /* in is the index of the next ASCII code point to be
           consumed, and out is the number of code points in the
           output array.  */

        /* Decode a generalized variable-length integer into delta,
           which gets added to i.  The overflow checking is easier if
           we increase i as we go, then subtract off its starting
           value at the end to obtain delta.  */

        for ( oldi = i, w = 1, k = base; ; k += base ) {
            digit = decodeDigit( input[in++] );
            if (digit >= base)
                return input;
            if (digit > (UINT_MAX - i) / w)
                return input;
            i += digit * w;
            t = k <= bias /* + tmin */ ? tmin :     /* +tmin not needed */
                k >= bias + tmax ? tmax : k - bias;
            if (digit < t)
                break;
            if (w > UINT_MAX / (base - t))
                return input;
            w *= (base - t);
        }

        bias = adapt( i - oldi, result.length() + 1, oldi == 0 );

        /* i was supposed to wrap around from out+1 to 0, incrementing
           n each time, so we'll fix that now: */

        if ( i / (result.length() + 1) > UINT_MAX - n )
            return input;
        n += i / (result.length() + 1);
        i %= (result.length() + 1);

        /* Insert n at position i of the output: */

        if ( i > result.length() )
            return input;

        UString after = result.mid( i );
        result = result.mid( 0, i );
        result.append( n );
        result.append( after );
    }

    return result;
}


