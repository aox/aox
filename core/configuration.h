// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include "string.h"
#include "list.h"
#include "log.h"


class Configuration
    : public Garbage
{
private:
    Configuration();
public:
    static void setup( const String &, bool = false );
    static void report();

    enum CompileTimeSetting {
        ConfigDir,
        PidFileDir,
        BinDir,
        SbinDir,
        ManDir,
        LibDir,
        InitDir,
        OryxUser,
        OryxGroup,
        PgUser,
        DefaultDbAddress,
        // additional settings go ABOVE THIS LINE
        Version, LastSetting = Version
    };

    static const char * compiledIn( CompileTimeSetting );
    static String configFile();

    enum Scalar {
        DbPort,
        TlsProxyPort,
        LogPort,
        OcdPort,
        OcAdminPort,
        PopPort,
        ImapPort,
        ImapsPort,
        SmtpPort,
        LmtpPort,
        SmtpSubmitPort,
        HttpPort,
        ServerProcesses,
        DbMaxHandles,
        DbHandleInterval,
        ManageSievePort,
        UndeleteTime,
        SmartHostPort,
        // additional scalars go ABOVE THIS LINE
        NumScalars
    };
    static uint scalar( Scalar );
    static bool present( Scalar );
    static const char * name( Scalar );

    enum Text {
        Db, // must be first, see addressVariables()
        DbName,
        DbOwner,
        DbOwnerPassword,
        DbUser,
        DbPassword,
        DbAddress,
        Hostname,
        JailUser,
        JailGroup,
        JailDir,
        AllowPlaintextPasswords,
        LogFile,
        TlsProxyAddress,
        LogAddress,
        OcdAddress,
        OcAdminAddress,
        PopAddress,
        ImapAddress,
        ImapsAddress,
        SmtpAddress,
        LmtpAddress,
        SmtpSubmitAddress,
        HttpAddress,
        TlsCertFile,
        LogLevel,
        LogfileMode,
        ArchivePrefix,
        WebmailPrefix,
        FaviconURL,
        WebmailCSS,
        WebmailJS,
        MessageCopy,
        MessageCopyDir,
        EntropySource,
        ManageSieveAddress,
        SmartHostAddress,
        // additional texts go ABOVE THIS LINE
        NumTexts
    };
    static String text( Text );
    static bool present( Text );
    static const char * name( Text );

    enum Toggle {
        Security,
        UseIPv4,
        UseIPv6,
        UseTls,
        UseSmtp,
        UseLmtp,
        UseSmtpSubmit,
        UseImap,
        UseImaps,
        UseHttp,
        UsePop,
        AuthPlain,
        AuthCramMd5,
        AuthDigestMd5,
        AuthAnonymous,
        AcceptAnyHttpHost,
        AnnounceDraftSupport,
        UseSieve,
        // additional toggles go ABOVE THIS LINE
        NumToggles
    };
    static bool toggle( Toggle );
    static bool present( Toggle );
    static const char * name( Toggle );

    static String hostname() { return text( Hostname ); }

    static void add( const String & );

    static void read( const String &, bool );

    static List<Text> * addressVariables();

private:
    static String osHostname();

    static void log( const String &, Log::Severity );

    static void parseScalar( uint, const String & );
    static void parseText( uint, const String & );
    static void parseToggle( uint, const String & );

    static class ConfigurationData * d;
};


#endif
