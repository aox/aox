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
    String::Encoding encoding() const;

    String data() const;
    void setData( const String & );

    UString text() const;
    void setText( const UString & );

    Message *rfc822() const;
    void setRfc822( Message * );

    uint numBytes() const;
    void setNumBytes( uint );

    uint numLines() const;
    void setNumLines( uint );

    String asText() const;

private:
    class BodypartData * d;
    friend class Message;

    Bodypart();
    static void parseMultiPart( uint, uint, const String &,
                                const String &, bool,
                                List< Bodypart > *, Bodypart *,
                                String & );
    static Bodypart *parseBodypart( uint, uint, const String &,
                                    Header *, String & );
};


#endif
