// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef PAGECOMPONENT_H
#define PAGECOMPONENT_H

#include "event.h"
#include "estring.h"
#include "list.h"


class UString;
class FrontMatter;
class WebPage;


class PageComponent
    : public EventHandler
{
public:
    PageComponent( const EString & );

    bool done() const;
    void execute();

    uint status() const;
    void setStatus( uint );

    WebPage * page() const;
    void setPage( WebPage * );

    EString contents() const;
    void setContents( const EString & );

    List<FrontMatter> * frontMatter() const;
    void addFrontMatter( FrontMatter * );

    EString divClass() const;

    static EString quoted( const EString & );
    static EString quoted( const UString & );
    static EString address( class Address * );
    static EString address( const UString & );

    uint uniqueNumber();

private:
    class PageComponentData * d;
};


#endif
