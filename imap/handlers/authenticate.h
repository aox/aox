// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef AUTHENTICATE_H
#define AUTHENTICATE_H

#include "command.h"
#include "estring.h"


class Authenticate
    : public Command
{
public:
    Authenticate();

    void parse();
    void execute();
    void read();

private:
    class SaslMechanism * m;
    EString * r;
    EString t;
};


#endif
