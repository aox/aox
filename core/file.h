// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FILE_H
#define FILE_H

#include "global.h"
#include "string.h"


class File {
public:
    enum Access {
        Read, Write, Append
    };
    File( const String &, File::Access, uint = 0 );
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
};


#endif
