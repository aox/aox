#ifndef ISO8859_H
#define ISO8859_H

#include "codec.h"


class Iso88591Codec: public Codec {
public:
    Iso88591Codec() : Codec( "ISO-8859-1" ) {}

public:
    String fromUnicode( const UString & );
    UString toUnicode( const String & );
};


class Iso88592Codec: public TableCodec {
public:
    Iso88592Codec();
};


class Iso88593Codec: public TableCodec {
public:
    Iso88593Codec();
};


class Iso88594Codec: public TableCodec {
public:
    Iso88594Codec();
};


class Iso88595Codec: public TableCodec {
public:
    Iso88595Codec();
};


class Iso88596Codec: public TableCodec {
public:
    Iso88596Codec();
};


class Iso88597Codec: public TableCodec {
public:
    Iso88597Codec();
};


class Iso88598Codec: public TableCodec {
public:
    Iso88598Codec();
};


class Iso88599Codec: public TableCodec {
public:
    Iso88599Codec();
};


class Iso885910Codec: public TableCodec {
public:
    Iso885910Codec();
};


class Iso885911Codec: public TableCodec {
public:
    Iso885911Codec();
};


class Iso885913Codec: public TableCodec {
public:
    Iso885913Codec();
};


class Iso885914Codec: public TableCodec {
public:
    Iso885914Codec();
};


class Iso885915Codec: public TableCodec {
public:
    Iso885915Codec();
};


class Iso885916Codec: public TableCodec {
public:
    Iso885916Codec();
};


#endif
