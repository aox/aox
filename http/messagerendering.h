// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MESSAGERENDERING_H
#define MESSAGERENDERING_H

#include "string.h"
#include "ustring.h"
#include "dict.h"


class MessageRendering
    : public Garbage
{
public:
    MessageRendering();

    void setTextPlain( const UString & );
    void setTextFlowed( const UString & );
    void setTextHtml( const String &, class Codec * );
    void setWebPage( class WebPage * );

    String asHtml();

    UString excerpt();

private:
    void renderHtml();
    void renderText();

    void render();

    Dict<String> * parseVariables( uint & );

private:
    class MessageRenderingData * d;
};


#endif
