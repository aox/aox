// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#ifndef METADATA_H
#define METADATA_H

#include "command.h"


class Metadata
    : public Command
{
public:
    enum Type { Get, Set };

    Metadata( Type );

    void parse();
    void execute();

private:
    bool accessible() const;

private:
    class MetadataData * d;
};


#endif
