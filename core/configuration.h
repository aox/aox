// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include <string.h>


class Configuration
{
private:
    Configuration();
public:
    static void setup( const String & );

    static String hostname();
    static String osHostname();

    static void report();

    static void ignore( const char * s1    , const char * s2 = 0,
                        const char * s3 = 0, const char * s4 = 0,
                        const char * s5 = 0, const char * s6 = 0,
                        const char * s7 = 0, const char * s8 = 0 );

    enum CompileTimeSetting {
        LogFile,
        ConfigDir,
        PidFileDir,
        BinDir,
        ManDir,
        LibDir,
        JailDir,
        DbAddress,
        DbUser,
        DbName,
        // additional settings go ABOVE THIS LINE
        Version, LastSetting = Version
    };

    static String compiledIn( CompileTimeSetting );

    class Variable {
    public:
        Variable(): ok( true ), s( false ) {}
        virtual ~Variable() {}

        bool valid() const { return ok || !s; }
        bool supplied() const { return s; }

        String name() const { return n; }

    protected:
        void init( const String & );
        void log( const String & );

    private:
        virtual bool setValue( const String & ) = 0;

    private:
        String n;
        bool ok;
        bool s;
    };

    class Scalar: public Variable {
    public:
        Scalar( const String &, int );

        operator int() const { return value; }
        operator uint() const { return (uint)value; }

    private:
        bool setValue( const String & );
        int value;
    };

    class Toggle: public Variable {
    public:
        Toggle( const String &, bool );

        operator bool() const { return value; }

    private:
        bool setValue( const String & );

    private:
        bool value;
    };

    class Text: public Variable {
    public:
        Text( const String &, const String & );
        Text( const String &, CompileTimeSetting );

        operator ::String() const { return value; }

    private:
        bool setValue( const String & );

    private:
        String value;
    };

    class Something {
    public:
        Something( const String & s3, const String & s4 )
            : s1( s3 ), s2( s4 ) {}
        String s1;
        String s2;
    };

private:
    void add( const String & );
    void read( const String & );

    class ConfigurationData * d;
    friend class Configuration::Variable;
};


#endif
