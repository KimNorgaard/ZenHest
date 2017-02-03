# ZenHest
Text based event console for Zenoss

# Requirements
ZenHest has a few dependencies:

   * urwid for drawing widgets
   * keyring for talking to the OS' keyring
   * clipboard for talking to the OS' clipboard

Requirements are listed in the requirements.txt file.

# Configuration
ZenHest is configured using environment variables.

## ZENHEST_URL (required)
Set ZENHEST_URL to the http(s)://server:port of your Zenoss installation.

## ZENHEST_USER and ZENHEST_KEYRING (optional)
If ZENHEST_USER is set, ZenHest will try to look up your password using your
system's keyring. By default it will look for an entry named 'zenhest' using
ZEN_USERNAME as the username.

If you want it to look elsewhere, set it with ZENHEST_KEYRING.

## ZENHEST_UPDATE_INTERVAL (optinal)
ZENHEST_UPDATE_INTERVAL sets how often (in seconds) ZenHest will poll Zenoss of
event updates. The default is 30.

## ZENHEST_EVENT_ACTION_ENABLED (optional)
Enabled ZenHest to call a command for events.
Uses ZENHEST_EVENT_ACTION_COMMAND as the command to trigger.
Set to 'yes', 'true' or '1' to enable. Default is 0.

## ZENHEST_EVENT_ACTION_COMMAND (optional)
Command to run on event actions. Defaults to '/bin/true'.

{} will be replaced by the currently selected event id.

Example:
export ZENHEST_EVENT_ACTION="/usr/bin/open https://my_handler_url/event/{}"


# Navigation

## General

    TAB     : Navigates between things
    q/Q/Esc : CLoses/quits things

## Main Window

    R   : Refresh event list
    f   : Show event filter menu
    A   : Acknowledge selected event
    C   : Close selected event
    O   : Reopen selected event
    J   : Trigger event action

## Main Window - Event Info focused

    y   : Copy selected line to clipboard
    Y   : Copy all lines to clipboard
