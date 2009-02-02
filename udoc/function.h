// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FUNCTION_H
#define FUNCTION_H

#include "global.h"
#include "estring.h"


class File;
class Class;
class DocBlock;


class Function
    : public Garbage
{
public:
    Function( const EString & type,
              const EString & name,
              const EString & arguments,
              bool constness,
              File * originFile, uint originLine );

    static Function * find( const EString & name,
                            const EString & arguments = "",
                            bool constness = false );

    Function * super() const;

    File * file() const { return f; }
    uint line() const { return l; }
    EString type() const { return t; }
    EString name() const { return n; }
    EString arguments() const { return args; }
    bool isConst() const { return cn; }

    void setArgumentList( const EString & );
    bool hasArgument( const EString & ) const;

    static EString typesOnly( const EString & );
    DocBlock * docBlock() const { return db; }
    void setDocBlock( DocBlock * docblock ) { db = docblock; }

    bool operator<=( const Function & ) const;

    Class * parent() const { return c; }

    void setOverload();
    bool hasOverload() const { return ol; }

private:
    Class * c;
    EString t, n, a, args;
    File * f;
    uint l;
    DocBlock * db;
    bool ol;
    bool cn;
};

#endif
