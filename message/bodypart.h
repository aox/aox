// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef BODYPART_H
#define BODYPART_H

#include "multipart.h"
#include "string.h"
#include "ustring.h"


class Header;
class Message;
class ContentType;


class Bodypart
    : public Multipart
{
public:
    Bodypart();
    Bodypart( uint, Multipart * );

    uint number() const;
    ContentType * contentType() const;
    String::Encoding encoding() const;
    String data() const;
    UString text() const;

    Message * rfc822() const;
    void setRfc822( Message * );

    void setNumBytes( uint );
    uint numBytes() const;
    void setNumLines( uint );
    uint numLines() const;

    String asText() const;

private:
    static void parseMultiPart( uint, uint, const String &,
                                const String &, bool,
                                List<Bodypart> *, Bodypart *,
                                String & );
    static Bodypart * parseBodypart( uint, uint, const String &, Header *,
                                     String & );
    void setText( const UString & );
    void setData( const String & );

private:
    class BodypartData * d;
    friend class Message;
    friend class MessageData;
    friend class MessageHeaderFetcher;
    friend class MessageBodyFetcher;
};


#endif
