// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef COPY_H
#define COPY_H


#include "command.h"


class Copy
    : public Command
{
public:
    Copy( bool );
    void parse();
    void execute();

protected:
    void setMove();

private:
    class CopyData * d;
};


#endif
