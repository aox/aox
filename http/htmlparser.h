// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef HTMLPARSER_H
#define HTMLPARSER_H

#include "global.h"
#include "list.h"
#include "dict.h"


class EString;
class UString;
class UStringList;


class HtmlNode
    : public Garbage
{
public:
    HtmlNode( HtmlNode *, const EString & = "" );

    HtmlNode * parent() const;
    void setParent( HtmlNode * );

    List< HtmlNode > * children() const;
    Dict< EString > * attributes() const;

    EString tag() const;
    void setTag( const EString & );
    UString & text() const;
    void setText( const UString & );
    EString htmlclass() const;
    void setHtmlClass( const EString & );
    EString href() const;
    void setHref( const EString & );

    bool isKnown() const;
    bool isBlock() const;
    bool isInline() const;

    void clean();

    void findExcerpt( UStringList * ) const;
    EString rendered() const;

private:
    class HtmlNodeData * d;

    void addChild( HtmlNode * );
};


class HtmlParser
    : public Garbage
{
public:
    HtmlParser( const EString &, class Codec * );

    HtmlNode * rootNode() const;

private:
    class HtmlParserData * d;

    void parse();
    void parseAttributes( Dict<EString> *, uint & );
};


#endif
