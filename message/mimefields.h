// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MIMEFIELDS_H
#define MIMEFIELDS_H

#include "field.h"
#include "string.h"
#include "stringlist.h"


class Parser822;


class MimeField
    : public HeaderField
{
protected:
    MimeField( HeaderField::Type );

public:
    StringList *parameters() const;
    String parameterString() const;
    String parameter( const String & ) const;
    void addParameter( const String &, const String & );
    void removeParameter( const String & );
    void parseParameters( Parser822 * );

    String rfc822() const;
    UString value() const;

    virtual String baseValue() const = 0;

private:
    class MimeFieldData *d;
};


class ContentType
    : public MimeField
{
public:
    ContentType();
    virtual ~ContentType();

    void parse( const String & );

    String type() const;
    String subtype() const;

    String baseValue() const;

private:
    String t, st;
};


class ContentTransferEncoding
    : public MimeField
{
public:
    ContentTransferEncoding();

    void parse( const String & );

    void setEncoding( String::Encoding );
    String::Encoding encoding() const;

    String baseValue() const;

private:
    String::Encoding e;
};


class ContentDisposition
    : public MimeField
{
public:
    ContentDisposition();

    void parse( const String & );

    enum Disposition { Inline, Attachment };
    Disposition disposition() const;

    String baseValue() const;

private:
    String d;
};


class ContentLanguage
    : public MimeField
{
public:
    ContentLanguage();
    virtual ~ContentLanguage();

    void parse( const String & );

    const StringList *languages() const;

    String baseValue() const;

private:
    StringList l;
};


#endif
