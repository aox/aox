// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FUNCTION_H
#define FUNCTION_H

#include "global.h"
#include "string.h"


class File;
class Class;
class DocBlock;


class Function
{
public:
    Function( const String & type,
              const String & name,
              const String & arguments,
              File * originFile, uint originLine );

    static Function * find( const String & name,
                            const String & arguments = "" );

    Function * super() const;

    File * file() const { return f; }
    uint line() const { return l; }
    String type() const { return t; }
    String name() const { return n; }
    String arguments() const { return args; }

    void setArgumentList( const String & );
    bool hasArgument( const String & ) const;

    static String typesOnly( const String & );
    DocBlock * docBlock() const { return db; }
    void setDocBlock( DocBlock * docblock ) { db = docblock; }

    bool operator<=( const Function & ) const;

    Class * parent() const { return c; }

    void setOverload();
    bool hasOverload() const { return ol; }

private:
    Class * c;
    String t, n, a, args;
    File * f;
    uint l;
    DocBlock * db;
    bool ol;
};

#endif
