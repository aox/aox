// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef HTMLPARSER_H
#define HTMLPARSER_H

#include "global.h"
#include "list.h"
#include "dict.h"


class String;
class UString;
class UStringList;


class HtmlNode
    : public Garbage
{
public:
    HtmlNode( HtmlNode *, const String & = "" );

    HtmlNode * parent() const;
    void setParent( HtmlNode * );

    List< HtmlNode > * children() const;
    Dict< String > * attributes() const;

    String tag() const;
    void setTag( const String & );
    UString & text() const;
    void setText( const UString & );
    String htmlclass() const;
    void setHtmlClass( const String & );
    String href() const;
    void setHref( const String & );

    bool isKnown() const;
    bool isBlock() const;
    bool isInline() const;

    void clean();

    void findExcerpt( UStringList * ) const;
    String rendered() const;

private:
    class HtmlNodeData * d;

    void addChild( HtmlNode * );
};


class HtmlParser
    : public Garbage
{
public:
    HtmlParser( const String &, class Codec * );

    HtmlNode * rootNode() const;

private:
    class HtmlParserData * d;

    void parse();
    void parseAttributes( Dict<String> *, uint & );
};


#endif
