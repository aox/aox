// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SERVER_H
#define SERVER_H

#include "global.h"
#include "event.h"


class String;


class Server
    : public EventHandler
{
public:
    Server( const char *, int, char *[] );

    enum ChrootMode {
        JailDir, LogDir, MessageCopyDir
    };

    void setChrootMode( ChrootMode );

    enum Stage {
        Configuration,
        Files,
        LogSetup,
        Loop,
        Report,
        Fork,
        PidFile,
        Startup,
        LogStartup,
        Secure,
        Finish // MUST BE LAST
    };

    void setup( Stage );
    void run();
    void execute();

    static String name();

private:
    static class ServerData * d;

    void configuration();
    void files();
    void loop();
    void logSetup();
    void fork();
    void pidFile();
    void startup();
    void logStartup();
    void secure();
};


#endif
