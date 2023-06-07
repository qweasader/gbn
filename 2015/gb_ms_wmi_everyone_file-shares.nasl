###############################################################################
# OpenVAS Vulnerability Test
#
# Get Windows File-Shares, shared for Everyone
#
# Authors:
# Thomas Rotter <Thomas.Rotter@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96198");
  script_version("2021-05-07T12:04:10+0000");
  script_tag(name:"last_modification", value:"2021-05-07 12:04:10 +0000 (Fri, 07 May 2021)");
  script_tag(name:"creation_date", value:"2015-09-08 13:13:18 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Get Windows File-Shares, shared for Everyone");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_ms_wmi_accessible_shares.nasl", "lsc_options.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("WMI/Accessible_Shares");
  script_exclude_keys("win/lsc/disable_win_cmd_exec");

  script_tag(name:"summary", value:"Get Windows File-Shares, shared for Everyone.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");

if( get_kb_item( "win/lsc/disable_win_cmd_exec" ) )
  exit( 0 );

host    = get_host_ip();
usrname = get_kb_item( "SMB/login" );
passwd  = get_kb_item( "SMB/password" );
shares  = get_kb_item( "WMI/Accessible_Shares" );
if( ! host || ! usrname || ! passwd ) exit( 0 );

domain  = get_kb_item( "SMB/domain" );
# nb: wmi_connect and win_cmd_exec needs a different syntax for a domain user
if( domain ) {
  wmiusrname = domain + '\\' + usrname;
  wincmdexecusrname = domain + '/' + usrname;
} else {
  wmiusrname = usrname;
  wincmdexecusrname = usrname;
}

handle = wmi_connect( host:host, username:wmiusrname, password:passwd );
if( ! handle ) exit( 0 );

query = "select Name from Win32_SystemAccount where SID='S-1-1-0'";

EveryonesName = wmi_query( wmi_handle:handle, query:query );
if( ! EveryonesName ) {
  wmi_close( wmi_handle:handle );
  exit( 0 );
}

se = split( EveryonesName, keep:FALSE );
se = split( se[1], sep:'|', keep:FALSE );
se = se[1];

sl = split( shares, keep:FALSE );

# nb: Starting with 1 as sl[0] contains the header
for( a = 1; a < max_index( sl ); a++ ) {

  READ   = NULL;
  CHANGE = NULL;
  FULL   = NULL;
  RES    = NULL;

  s    = split( sl[a], sep:'|', keep:FALSE );
  fold = eregmatch( pattern:":", string:s[2] );
  desc = s[0];
  name = s[1];
  path = s[2];
  if( isnull( desc ) || desc == "" ) desc = "None";

  if( fold ) {
    c   = "net share " + name;
    val = win_cmd_exec( cmd:c, password:passwd, username:wincmdexecusrname );

    READ   = eregmatch( string:val, pattern:se + ", READ" );
    CHANGE = eregmatch( string:val, pattern:se + ", CHANGE" );
    FULL   = eregmatch( string:val, pattern:se + ", FULL" );

    if( READ[0] )   RES = name + "|" + path + "|" +  READ[0] + "|" + desc + '\n';
    if( CHANGE[0] ) RES = name + "|" + path + "|" +  CHANGE[0] + "|" + desc + '\n';
    if( FULL[0] )   RES = name + "|" + path + "|" +  FULL[0] + "|" + desc + '\n';

    result += RES;
  }
}

if( result ) {
  report  = "The following File-Shares are shared for Everyone (local name: '" + se + "'):" + '\n\n';
  report += 'Name|Path|Access|Description\n' + result;
  log_message( port:0, data:report );
}

wmi_close( wmi_handle:handle);
exit( 0 );
