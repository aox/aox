// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FRONTMATTER_H
#define FRONTMATTER_H

#include "estring.h"


class FrontMatter
    : public EString
{
public:
    FrontMatter( const EString & );

    EString element() const;

    static FrontMatter * title( const EString & );
    static FrontMatter * styleSheet();
    static FrontMatter * style( const EString & );
    static FrontMatter * jQuery();
    static FrontMatter * script( const EString & );
    static FrontMatter * jsToggles();

private:
    class FrontMatterData * d;
};


#endif
