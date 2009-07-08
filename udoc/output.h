// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef OUTPUT_H
#define OUTPUT_H

#include "estring.h"


class Function;
class Class;
class Intro;


class Output
    : public Garbage
{
public:
    static void startHeadline( Intro * );
    static void startHeadline( Class * );
    static void startHeadline( Function * );
    static void endParagraph();
    static void addText( const EString & );
    static void addLink( const EString &, const EString & );
    static void addArgument( const EString & );
    static void addFunction( const EString &, Function * );
    static void addClass( const EString &, Class * );
    static void addSpace();
    static void setOwner( const EString & );
    static EString owner();
    static void setOwnerHome( const EString & );
    static EString ownerHome();
};


#endif
