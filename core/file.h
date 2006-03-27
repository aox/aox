// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FILE_H
#define FILE_H

#include "global.h"
#include "string.h"


class File
    : public Garbage
{
public:
    enum Access {
        Read, Write, Append, ExclusiveWrite
    };
    File( int );
    File( const String &, uint = 0 );
    File( const String &, File::Access, uint = 0644 );
    ~File();

    bool valid() const;

    String name() const;
    String contents() const;

    uint modificationTime() const;

    void write( const String & );

    static void setRoot( const String & );
    static String root();
    static String chrooted( const String & );

    static void unlink( String );

private:
    class FileData * d;
    void init( const String &, File::Access, uint, uint );
};


#endif
