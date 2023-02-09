// This file is a slight adaption of the sample code in RFC 3492;
// no copyright is claimed.

#ifndef PUNYCODE_H
#define PUNYCODE_H

#include "global.h"

class UString;


class Punycode
    : public Garbage
{
public:

    enum Status {
        Success = 0,
        BadInput = 1, // Input is invalid.
        BigOutput = 2, // Output would exceed the space provided.
        Overflow = 3 // Wider integers needed to process input.
    };

    //static EString encode(UString input);
    static UString decode(const UString & input);
};


#endif
