# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96199");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-03-12 09:32:24 +0200 (Wed, 12 Mar 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Get Windows File-Shares over WMI");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Windows");
  script_dependencies("gb_wmi_access.nasl");
  script_mandatory_keys("WMI/access_successful");

  script_tag(name:"summary", value:"Get Windows File-Shares over WMI.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");

host    = get_host_ip();
usrname = get_kb_item( "SMB/login" );
passwd  = get_kb_item( "SMB/password" );
if( ! host || ! usrname || ! passwd ) exit( 0 );

domain  = get_kb_item( "SMB/domain" );
if( domain ) usrname = domain + '\\' + usrname;

handle = wmi_connect( host:host, username:usrname, password:passwd );
if( ! handle ) exit( 0 );

# nb: 2015/gb_ms_wmi_everyone_file-shares.nasl relies on the
# three items returned here so update this as well if more
# objects are queried here.
query = "select Description, Name, Path from Win32_share";

sharelist = wmi_query( wmi_handle:handle, query:query );
wmi_close( wmi_handle:handle );

if( sharelist ) {
  set_kb_item( name:"WMI/Accessible_Shares", value:sharelist );
  report = 'The following File-Shares were found:\n\n' + sharelist;
  log_message( port:0, data:report );
}

exit( 0 );
