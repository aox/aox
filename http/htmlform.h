// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef HTMLFORM_H
#define HTMLFORM_H

#include "global.h"
#include "string.h"

class UString;


class HtmlForm
    : public Garbage
{
public:
    HtmlForm( const String & = "", const String & = "post" );

    void addField( const String &, const String & = "text",
                   const String & = "", bool = false );
    void requireField( const String &, const String & = "text",
                       const String & = "" );

    void setValue( const String &, const UString & );
    void setValuesFrom( class WebPage * );
    UString getValue( const String & );

    bool filled() const;
    void clear();

    String html() const;

private:
    class HtmlFormData * d;
};


#endif
