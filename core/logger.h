// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LOGGER_H
#define LOGGER_H

class String;

#include "global.h"


class Logger
    : public Garbage
{
public:
    Logger();
    virtual void send( const String & ) = 0;
    virtual ~Logger();

    virtual String name() const;

    static Logger *global();
};


#endif
