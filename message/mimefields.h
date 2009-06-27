// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef MIMEFIELDS_H
#define MIMEFIELDS_H

#include "field.h"
#include "estring.h"
#include "estringlist.h"


class EmailParser;


class MimeField
    : public HeaderField
{
protected:
    MimeField( HeaderField::Type );

public:
    EStringList *parameters() const;
    EString parameterString() const;
    EString parameter( const EString & ) const;
    void addParameter( const EString &, const EString & );
    void removeParameter( const EString & );
    void parseParameters( EmailParser * );

    EString rfc822() const;
    UString value() const;

    virtual EString baseValue() const = 0;

private:
    class MimeFieldData *d;
};


class ContentType
    : public MimeField
{
public:
    ContentType();
    virtual ~ContentType();

    void parse( const EString & );

    EString type() const;
    EString subtype() const;

    EString baseValue() const;

private:
    EString t, st;
};


class ContentTransferEncoding
    : public MimeField
{
public:
    ContentTransferEncoding();

    void parse( const EString & );

    void setEncoding( EString::Encoding );
    EString::Encoding encoding() const;

    EString baseValue() const;

private:
    EString::Encoding e;
};


class ContentDisposition
    : public MimeField
{
public:
    ContentDisposition();

    void parse( const EString & );

    enum Disposition { Inline, Attachment };
    Disposition disposition() const;

    EString baseValue() const;

private:
    EString d;
};


class ContentLanguage
    : public MimeField
{
public:
    ContentLanguage();
    virtual ~ContentLanguage();

    void parse( const EString & );

    const EStringList *languages() const;

    EString baseValue() const;

private:
    EStringList l;
};


#endif
