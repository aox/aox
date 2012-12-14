// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef SERVER_H
#define SERVER_H

#include "global.h"


class EString;


class Server
    : public Garbage
{
public:
    Server( const char *, int, char *[] );

    enum ChrootMode {
        JailDir, LogDir
    };

    void setChrootMode( ChrootMode );

    enum Stage {
        Configuration,
        NameResolution,
        Files,
        LogSetup,
        Loop,
        Report,
        PidFile,
        LogStartup,
        Finish // MUST BE LAST
    };

    void setup( Stage );
    void run();

    static EString name();
    static bool useCache();

    static void killChildren();

    static void secure();
    static void addChild( class Connection * );

private:
    static class ServerData * d;

    void configuration();
    void nameResolution();
    void files();
    void loop();
    void logSetup();
    void fork();
    void pidFile();
    void logStartup();
    void maintainChildren();
};


#endif
