#ifndef FILE_H
#define FILE_H

#include "global.h"
#include "string.h"


class File {
public:
    enum Access {
        Read, Write
    };
    File( const String &, Access, uint = 0 );
    ~File();

    bool valid() const;

    String name() const;
    String contents() const;

    uint modificationTime() const;

    void write( const String & );

    static void unlink( String );

private:
    class FileData * d;
};


#endif
