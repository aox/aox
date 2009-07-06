// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef STDERRLOGGER_H
#define STDERRLOGGER_H

#include "logger.h"


class StderrLogger
    : public Logger
{
public:
    StderrLogger( const EString & name, uint verbosity );

    void send( const EString &, Log::Severity, const EString & );

    virtual EString name() const;

private:
    EString n;
    uint v;
};


#endif
