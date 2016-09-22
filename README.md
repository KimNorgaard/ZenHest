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

## Main Window - Event Info focused
y   : Copy selected line to clipboard
Y   : Copy all lines to clipboard

