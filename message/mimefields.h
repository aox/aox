// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MIMEFIELDS_H
#define MIMEFIELDS_H

#include "stringlist.h"

class Parser822;


class MimeField {
public:
    MimeField();

    void parse( Parser822 * );

    StringList * parameterList() const;
    String parameter( const String & ) const;

    bool valid() const;
    void setValid( bool );

    void removeParameter( const String & );
    void addParameter( const String &, const String & );

private:
    class MimeFieldData * d;
};


class ContentType
    : public MimeField
{
public:
    ContentType( const String & );
    String type() const;
    String subtype() const;

private:
    String t, st;
};


class ContentTransferEncoding
    : public MimeField
{
public:
    ContentTransferEncoding( const String & );
    void setEncoding( String::Encoding );
    String::Encoding encoding() const;

private:
    String::Encoding e;
};


class ContentDisposition
    : public MimeField
{
public:
    ContentDisposition( const String & );

    enum Disposition {
        Inline,
        Attachment
    };

    Disposition disposition() const;

private:
    Disposition d;
};


class ContentLanguage
    : public MimeField
{
public:
    ContentLanguage( const String & );
    const StringList *languages() const;

private:
    StringList l;
};


#endif
