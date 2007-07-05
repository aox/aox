// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SERVERS_H
#define SERVERS_H

#include "aoxcommand.h"
#include "list.h"


class Start
    : public AoxCommand
{
public:
    Start( StringList * );
    void execute();

private:
    class Query * q;
    bool startServer( const char * );
};


class Stop
    : public AoxCommand
{
public:
    Stop( StringList * );
    void execute();
};


class Restart
    : public AoxCommand
{
public:
    Restart( StringList * );
    void execute();
};


class ShowStatus
    : public AoxCommand
{
public:
    ShowStatus( StringList * );
    void execute();
};


class ShowBuild
    : public AoxCommand
{
public:
    ShowBuild( StringList * );
    void execute();
};


class ShowConfiguration
    : public AoxCommand
{
public:
    ShowConfiguration( StringList * );
    void execute();

private:
    void addVariable( SortedList<String> *,
                      String, String, String, bool );
};


#endif
