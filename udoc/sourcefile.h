#ifndef SOURCEFILE_H
#define SOURCEFILE_H

#include "file.h"


class Parser;
class Function;


class SourceFile: public File
{
public:
    SourceFile( const String & );

    void parse();

private:
    Function * function( Parser * );
};


#endif
