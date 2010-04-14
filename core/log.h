// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef LOG_H
#define LOG_H

#include "global.h"
#include "estring.h"

class EString;


class Log
    : public Garbage
{
public:
    enum Severity { Debug, Info, Significant, Error, Disaster };

    Log();
    Log( Log * );
    void log( const EString &, Severity = Info );
    EString id();

    Log * parent() const;
    bool isChildOf( Log * ) const;

    static void setLogLevel( Severity );
    static const char * severity( Severity );
    static bool disastersYet();

private:
    EString ide;
    uint children;
    Log * p;
};


void log( const EString &, Log::Severity = Log::Info );


#endif
