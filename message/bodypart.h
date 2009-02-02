// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef BODYPART_H
#define BODYPART_H

#include "multipart.h"


class EString;
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

    uint id() const;
    void setId( uint );

    ContentType * contentType() const;
    EString::Encoding contentTransferEncoding() const;

    EString data() const;
    void setData( const EString & );

    Message * message() const;
    void setMessage( Message * );

    bool isBodypart() const;

    UString text() const;
    void setText( const UString & );

    uint numBytes() const;
    void setNumBytes( uint );

    uint numEncodedBytes() const;
    void setNumEncodedBytes( uint );

    uint numEncodedLines() const;
    void setNumEncodedLines( uint );

    EString asText() const;

    EString error() const;

    static Bodypart *parseBodypart( uint, uint, const EString &,
                                    Header *, Multipart * );

    static void parseMultipart( uint, uint, const EString &,
                                const EString &, bool,
                                List< Bodypart > *, Multipart * );
private:
    class BodypartData * d;
    friend class Message;

    Bodypart();
};


#endif
