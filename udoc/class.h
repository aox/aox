// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef CLASS_H
#define CLASS_H

class File;
class Function;
class DocBlock;

#include "estring.h"
#include "list.h"


class Class
    : public Garbage
{
public:
    Class( const EString &, File *, uint );

    static Class * find( const EString & );
    static void buildHierarchy();
    static void output();

    File * file() const;
    uint line() const;

    void setParent( const EString & );
    Class * parent() const { return super; }

    EString name() const { return n; }

    void insert( Function * );

    bool operator<=( const Class & ) const;

    void generateOutput();

    void setDocBlock( DocBlock * docblock ) { db = docblock; }
    void setSource( File * file , uint line ) { f = file; l = line; }

    List<Class> * subclasses() const;
    List<Function> * members();

private:
    EString n;
    File * f;
    uint l;
    Class * super;
    SortedList<Class> * sub;
    EString superclassName;
    SortedList<Function> m;
    DocBlock * db;
    bool done;
};


#endif
