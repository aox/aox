#ifndef HEADERFILE_H
#define HEADERFILE_H

#include "file.h"


class HeaderFile: public File
{
public:
    HeaderFile( const String & );

    static HeaderFile * find( const String & );

    void parse();
};


#endif
