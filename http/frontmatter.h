// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FRONTMATTER_H
#define FRONTMATTER_H

#include "string.h"


class FrontMatter
    : public String
{
public:
    FrontMatter( const String & );

    String element() const;

    static FrontMatter * title( const String & );
    static FrontMatter * styleSheet();
    static FrontMatter * style( const String & );
    static FrontMatter * jQuery();
    static FrontMatter * script( const String & );
    static FrontMatter * jsToggles();

private:
    class FrontMatterData * d;
};


#endif
