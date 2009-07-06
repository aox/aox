// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef LOGGER_H
#define LOGGER_H

class EString;

#include "global.h"
#include "log.h"


class Logger
    : public Garbage
{
public:
    Logger();
    virtual ~Logger();

    virtual void send( const EString &, Log::Severity, const EString & ) = 0;

    virtual EString name() const;

    static Logger *global();
};


#endif
