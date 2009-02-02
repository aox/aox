// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef HTMLFORM_H
#define HTMLFORM_H

#include "global.h"
#include "estring.h"

class UString;


class HtmlForm
    : public Garbage
{
public:
    HtmlForm( const EString & = "", const EString & = "post" );

    void addField( const EString &, const EString & = "text",
                   const EString & = "", bool = false );
    void requireField( const EString &, const EString & = "text",
                       const EString & = "" );

    void setValue( const EString &, const UString & );
    void setValuesFrom( class WebPage * );
    UString getValue( const EString & );

    bool filled() const;
    void clear();

    EString html() const;

private:
    class HtmlFormData * d;
};


#endif
