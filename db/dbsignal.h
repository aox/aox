// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef DBSIGNAL_H
#define DBSIGNAL_H

#include "estringlist.h"

class EventHandler;


class DatabaseSignal
    : public Garbage
{
public:
    DatabaseSignal( const EString &, EventHandler * );

    static void notifyAll( const EString & );

    static EStringList * names();

private: // noone can destroy this
    ~DatabaseSignal();

private:
    class DatabaseSignalData * d;
};


#endif
