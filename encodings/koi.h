// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef KOI_H
#define KOI_H

#include "codec.h"


class Koi8RCodec: public TableCodec {
public:
    Koi8RCodec();
};


class Koi8UCodec: public TableCodec {
public:
    Koi8UCodec();
};


#endif
