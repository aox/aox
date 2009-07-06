// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef FILE_H
#define FILE_H

#include "global.h"
#include "estring.h"
#include "estringlist.h"


class File
    : public Garbage
{
public:
    enum Access {
        Read, Write, Append, ExclusiveWrite
    };
    File( int );
    File( const EString &, uint = 0 );
    File( const EString &, File::Access, uint = 0644 );
    ~File();

    bool valid() const;

    EString name() const;
    EString contents() const;
    EStringList * lines();

    uint modificationTime() const;

    void write( const EString & );

    static void setRoot( const EString & );
    static EString root();
    static EString chrooted( const EString & );

    static void unlink( EString );

private:
    class FileData * d;
    void init( const EString &, File::Access, uint, uint );
};


#endif
