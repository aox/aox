// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SERVER_H
#define SERVER_H


class Server
{
public:
    Server( const char * name );

    enum Stage {
        Test, // MUST BE FIRST
        Configuration,
        Files,
        Loop,
        Report,
        PidFile,
        LogStartup,
        Secure,
        Finish // MUST BE LAST
    };

    void setup( Stage );

    void execute();

private:
    void test();
    void configuration();
    void loop();
    void report();
    void pidFile();
    void files();
    void logStartup();
    void secure();

private:
    class ServerData * d;
};


#endif
