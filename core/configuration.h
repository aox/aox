// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include "estring.h"
#include "list.h"
#include "log.h"


class Configuration
    : public Garbage
{
private:
    Configuration();
public:
    static void setup( const EString &, bool = false );
    static void report();

    enum CompileTimeSetting {
        ConfigDir,
        PidFileDir,
        BinDir,
        SbinDir,
        ManDir,
        LibDir,
        InitDir,
        AoxUser,
        AoxGroup,
        PgUser,
        DefaultDbAddress,
        // additional settings go ABOVE THIS LINE
        Version, LastSetting = Version
    };

    static const char * compiledIn( CompileTimeSetting );
    static EString configFile();

    enum Scalar {
        DbPort,
        TlsProxyPort,
        LogPort,
        PopPort,
        ImapPort,
        ImapsPort,
        PopsPort,
        SmtpPort,
        LmtpPort,
        SmtpSubmitPort,
        SmtpsPort,
        HttpPort,
        HttpsPort,
        ServerProcesses,
        DbMaxHandles,
        DbHandleInterval,
        DbHandleTimeout,
        ManageSievePort,
        UndeleteTime,
        SmartHostPort,
        StatisticsPort,
        LdapServerPort,
        MemoryLimit,
        // additional scalars go ABOVE THIS LINE
        NumScalars
    };
    static uint scalar( Scalar );
    static bool present( Scalar );
    static const char * name( Scalar );

    enum Text {
        Db, // must be first, see addressVariables()
        DbName,
        DbSchema,
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
        AllowPlaintextAccess,
        LogFile,
        TlsProxyAddress,
        LogAddress,
        PopAddress,
        ImapAddress,
        ImapsAddress,
        PopsAddress,
        SmtpAddress,
        LmtpAddress,
        SmtpSubmitAddress,
        SmtpsAddress,
        HttpAddress,
        HttpsAddress,
        TlsCertFile,
        TlsCertLabel,
        TlsCertSecret,
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
        AddressSeparator,
        StatisticsAddress,
        LdapServerAddress,
        // additional texts go ABOVE THIS LINE
        NumTexts
    };
    static EString text( Text );
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
        UseSmtps,
        UseImap,
        UseImaps,
        UsePops,
        UseHttp,
        UseHttps,
        UsePop,
        SubmitCopyToSender,
        AuthPlain,
        AuthLogin,
        AuthCramMd5,
        AuthDigestMd5,
        AuthAnonymous,
        AcceptAnyHttpHost,
        UseSieve,
        UseWebmail,
        UseWebArchive,
        UseSubaddressing,
        UseStatistics,
        SoftBounce,
        CheckSenderAddresses,
        // additional toggles go ABOVE THIS LINE
        NumToggles
    };
    static bool toggle( Toggle );
    static bool present( Toggle );
    static const char * name( Toggle );

    static EString hostname() { return text( Hostname ); }

    static void add( const EString & );

    static void read( const EString &, bool );

    static List<Text> * addressVariables();

private:
    static EString osHostname();

    static void log( const EString &, Log::Severity );

    static void parseScalar( uint, const EString & );
    static void parseText( uint, const EString & );
    static void parseToggle( uint, const EString & );

    static class ConfigurationData * d;
};


#endif
