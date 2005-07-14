// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef BODYPART_H
#define BODYPART_H

#include "multipart.h"


class String;
class UString;
class Header;
class Message;
class ContentType;


class Bodypart
    : public Multipart
{
public:
    Bodypart( uint, Multipart * );

    uint number() const;

    ContentType * contentType() const;

    String data() const;
    void setData( const String & );

    UString text() const;
    void setText( const UString & );

    uint numBytes() const;
    void setNumBytes( uint );

    uint numEncodedBytes() const;
    void setNumEncodedBytes( uint );

    uint numEncodedLines() const;
    void setNumEncodedLines( uint );

    String asText() const;

private:
    class BodypartData * d;
    friend class Message;

    Bodypart();
    static void parseMultipart( uint, uint, const String &,
                                const String &, bool,
                                List< Bodypart > *, Bodypart *,
                                String & );
    static Bodypart *parseBodypart( uint, uint, const String &,
                                    Header *, String & );
};


#endif
