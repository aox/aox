#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include <string.h>


class Configuration
{
public:
    Configuration();
    Configuration( const String & );

    static Configuration * global();
    static void makeGlobal( const String & );

    static String hostname();

    void read( const String & );
    void report();

    class Variable {
    public:
        Variable(): ok( true ), s( false ) {}
        virtual ~Variable() {}

        bool valid() const { return ok || !s; }
        bool supplied() const { return s; }

    protected:
        void init( Configuration * c, const String & );

    private:
        virtual bool setValue( const String & ) = 0;

    private:
        bool ok;
        bool s;
    };

    class Scalar: public Variable {
    private:


    public:
        Scalar( const String &, int,
                Configuration * = Configuration::global() );

        operator int() const { return value; }
        operator unsigned int() const { return (uint)value; }

    private:
        bool setValue( const String & );
        int value;
    };

    class Toggle: public Variable {
    public:
        Toggle( const String &, bool,
                Configuration * = Configuration::global() );

        operator bool() const { return value; }

    private:
        bool setValue( const String & );

    private:
        bool value;
    };

    class Text: public Variable {
    public:
        Text( const String &, const String &,
              Configuration * = Configuration::global() );

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
    void clear();

    class ConfigurationData * d;
    friend class Configuration::Variable;
};


#endif
