// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SERVER_H
#define SERVER_H

class String;


class Server {
public:
    Server( const char *, int, char *[] );

    enum ChrootMode {
        JailDir, LogDir
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
        LogStartup,
        Secure,
        Finish // MUST BE LAST
    };

    void setup( Stage );
    void execute();

    static String name();

private:
    class ServerData * d;

    void configuration();
    void files();
    void loop();
    void logSetup();
    void fork();
    void pidFile();
    void logStartup();
    void secure();
};


#endif
