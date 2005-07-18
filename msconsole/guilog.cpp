// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "guilog.h"


/*! \class GuiLog guilog.h

    The GuiLog class redirects log lines to a suitable widget - which
    is generally not shown. Because of this, msconsole doesn't need to
    connect to the logd.
*/

GuiLog::GuiLog()
    : Logger()
{
    // nothing
}


void GuiLog::send( const String &,
                   Log::Facility, Log::Severity,
                   const String & )
{

}


void GuiLog::commit( const String &, Log::Severity )
{

}
