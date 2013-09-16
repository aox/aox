// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef HEADER_H
#define HEADER_H

#include "list.h"
#include "field.h"


class EString;
class Address;
class ContentType;
class ContentTransferEncoding;
class ContentDisposition;
class ContentLanguage;
class AddressField;
class Date;


class Header
    : public Garbage
{
public:
    enum Mode { Rfc2822, Mime };
    Header( Mode );

    Mode mode() const;
    bool valid() const;
    EString error() const;

    void add( HeaderField * );
    void add( const EString &, const EString & );
    void removeField( HeaderField::Type );
    void removeField( const char * );

    List< HeaderField > * fields() const;
    HeaderField * field( HeaderField::Type, uint = 0 ) const;
    HeaderField * field( const char *, uint = 0 ) const;
    AddressField * addressField( HeaderField::Type, uint = 0 ) const;

    Date * date( HeaderField::Type = HeaderField::Date ) const;
    EString subject() const;
    EString inReplyTo() const;
    EString messageId( HeaderField::Type = HeaderField::MessageId ) const;
    List< Address > * addresses( HeaderField::Type ) const;
    ContentType * contentType() const;
    ContentTransferEncoding * contentTransferEncoding() const;
    ContentDisposition * contentDisposition() const;
    ContentLanguage * contentLanguage() const;
    EString contentDescription() const;
    EString contentLocation() const;

    bool needsUnicode() const;

    void simplify();
    void repair();
    void repair( class Multipart *, const EString & );
    void fix8BitFields( class Codec * );

    EString asText( bool ) const;

    enum DefaultType { TextPlain, MessageRfc822 };
    void setDefaultType( DefaultType );
    DefaultType defaultType() const;

private:
    class HeaderData * d;

    void verify() const;
    void appendField( EString &, HeaderField *, bool avoidUtf8 ) const;
};


#endif
