// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef OUTPUT_H
#define OUTPUT_H

#include "string.h"


class Function;
class Class;


class Output
{
public:
    static void startHeadline( Class * );
    static void startHeadline( Function * );
    static void endParagraph();
    static void addText( const String & );
    static void addArgument( const String & );
    static void addFunction( const String &, Function * );
    static void addClass( const String &, Class * );
    static void addSpace();
    static void setOwner( const String & );
    static String owner();
    static void setOwnerHome( const String & );
    static String ownerHome();
};


#endif
