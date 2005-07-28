// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MULTIPART_H
#define MULTIPART_H

#include "list.h"

class Header;
class Message;
class Bodypart;
class ContentType;


class Multipart
    : public Garbage
{
public:
    Multipart();

    Header * header() const;
    void setHeader( Header * );

    Multipart * parent() const;
    void setParent( Multipart * );

    virtual Message * message() const;
    virtual void setMessage( Message * );

    virtual uint numEncodedBytes() const;
    virtual uint numEncodedLines() const;

    List< Bodypart > * children() const;

    void appendMultipart( String & ) const;
    void appendAnyPart( String &, const Bodypart *, ContentType * ) const;
    void appendTextPart( String &, const Bodypart *, ContentType * ) const;

private:
    Header * h;
    Multipart * p;
    Message * m;
    List< Bodypart > * parts;
};


#endif
