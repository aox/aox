// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef MESSAGERENDERING_H
#define MESSAGERENDERING_H

#include "estring.h"
#include "ustring.h"
#include "dict.h"


class MessageRendering
    : public Garbage
{
public:
    MessageRendering();

    void setTextPlain( const UString & );
    void setTextFlowed( const UString & );
    void setTextHtml( const EString &, class Codec * );
    void setWebPage( class WebPage * );

    EString asHtml();

    UString excerpt();

private:
    void renderHtml();
    void renderText();
    void render();

private:
    class MessageRenderingData * d;
};


#endif
