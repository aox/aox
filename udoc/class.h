#ifndef CLASS_H
#define CLASS_H

class File;
class Function;
class DocBlock;

#include "string.h"
#include "list.h"


class Class
{
public:
    Class( const String &, File *, uint );

    static Class * find( const String & );
    static void buildHierarchy();
    static void output();

    File * file() const;
    uint line() const;

    void setParent( const String & );
    Class * parent() const { return super; }

    String name() const { return n; }

    void insert( Function * );

    bool operator<=( const Class & ) const;

    void generateOutput();

    void setDocBlock( DocBlock * docblock ) { db = docblock; }
    void setSource( File * file , uint line ) { f = file; l = line; }

    List<Class> * subclasses() const;
    List<Function> * members();

private:
    String n;
    File * f;
    uint l;
    Class * super;
    SortedList<Class> * sub;
    String superclassName;
    SortedList<Function> m;
    DocBlock * db;
    bool done;
};


#endif
