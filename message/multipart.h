// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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
    virtual ~Multipart();

    Header * header() const;
    void setHeader( Header * );

    Multipart * parent() const;
    void setParent( Multipart * );

    virtual bool isMessage() const;
    virtual bool isBodypart() const;

    List< Bodypart > * children() const;

    void appendMultipart( EString &, bool, bool ) const;
    void appendAnyPart( EString &, const Bodypart *, ContentType *, bool, bool ) const;
    void appendTextPart( EString &, const Bodypart *, ContentType *, bool ) const;

    virtual void simplifyMimeStructure();
    bool needsUnicode() const;

    bool isPgpSigned();
    void setPgpSigned( bool );

private:
    Header * h;
    Multipart * p;
    List< Bodypart > * parts;
};


#endif
