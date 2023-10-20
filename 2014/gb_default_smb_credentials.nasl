# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804449");
  script_version("2023-09-12T05:05:19+0000");
  script_cve_id("CVE-1999-0503", "CVE-1999-0504", "CVE-1999-0505", "CVE-1999-0506", "CVE-2000-0222",
                "CVE-2005-3595");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-09-12 05:05:19 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"creation_date", value:"2014-07-04 17:14:10 +0530 (Fri, 04 Jul 2014)");
  script_name("SMB Brute Force Logins With Default Credentials");
  script_category(ACT_ATTACK);
  script_family("Brute force attacks");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("smb_authorization.nasl", "netbios_name_get.nasl",
                      "cifs445.nasl", "find_service.nasl", "logins.nasl",
                      "gb_default_credentials_options.nasl");
  script_require_keys("SMB/name", "SMB/transport");
  script_exclude_keys("default_credentials/disable_brute_force_checks");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"A number of known default credentials are tried for the login
  via the SMB protocol.");

  script_tag(name:"vuldetect", value:"Tries to login with a number of known default credentials via
  the SMB protocol.");

  script_tag(name:"solution", value:"Change the password as soon as possible.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_brute_force_checks" ) )
  exit( 0 );

include("smb_nt.inc");
include("smb_default_credentials.inc");
include("misc_func.inc");

function remote_login( smbLogin, passwd, smbDomain, smbName, smbPort ) {

  local_var smbLogin, passwd, smbDomain, smbName, smbPort;
  local_var soc, r, prot, uid, tid;

  soc = open_sock_tcp( smbPort );
  if( ! soc )
    return FALSE;

  r = smb_session_request( soc:soc, remote:smbName );
  if( ! r ) {
    close( soc );
    return FALSE;
  }

  prot = smb_neg_prot( soc:soc );
  if( ! prot ) {
    close( soc );
    return FALSE;
  }

  r = smb_session_setup( soc:soc, login:smbLogin, password:passwd, domain:smbDomain, prot:prot );
  if( ! r ) {
    close( soc );
    return FALSE;
  }

  uid = session_extract_uid( reply:r );
  if( ! uid ) {
    close( soc );
    return FALSE;
  }

  r = smb_tconx( soc:soc, name:smbName, uid:uid, share:"IPC$" );
  close( soc );

  if( r ) {
    return TRUE;
  } else {
    return FALSE;
  }
}

smbPort = kb_smb_transport();
if( ! smbPort )
  smbPort = 139;
if( ! get_port_state( smbPort ) )
  exit( 0 );

smbName = kb_smb_name();
if( ! smbName )
  smbName = "*SMBSERVER";

# nb: This is a check for always successful logins (unknown users mapped to guest) for random users.
for( i = 1; i < 4; i++ ) {

  u = rand_str( length:( 7 + i ), charset:'abcdefghijklmnopqrstuvwxyz' );
  p = rand_str( length:( 7 + i ), charset:'abcdefghijklmnopqrstuvwxyz0123456789' );

  login_defined = remote_login( smbLogin:u, passwd:p, smbDomain:"", smbName:smbName, smbPort:smbPort );
  if( login_defined )
    exit( 0 );

  sleep( 1 );
}

login_defined = remote_login( smbLogin:"", passwd:"", smbDomain:"", smbName:smbName, smbPort:smbPort );
if( login_defined )
  exit( 0 );

# nb: For currently unknown reasons a Samba Server on MacOS is accepting logins for the 'Guest' user with an empty password
# as well as with any of the Guest passwords defined in smb_default_credentials.inc. Both checks here should test this
# behavior to only report one single log entry or prevent having 50+ entries within the report.
login_defined = remote_login( smbLogin:"Guest", passwd:"", smbDomain:"", smbName:smbName, smbPort:smbPort );
if( login_defined ) {
  guest_empty = TRUE;
  report = string( "It was possible to login with the 'Guest' user and no/an empty password via the SMB protocol to the 'IPC$' share." );
  security_message( data:report, port:smbPort );
}

login_defined = remote_login( smbLogin:"Guest", passwd:rand_str( length:10, charset:'abcdefghijklmnopqrstuvwxyz0123456789' ), smbDomain:"", smbName:smbName, smbPort:smbPort );
if( login_defined )
  guest_all = TRUE;

foreach credential( credentials ) {

  user_pass = split( credential, sep:";", keep:FALSE );

  if( isnull( user_pass[0] ) || isnull( user_pass[1] ) )
    continue;

  smbLogin = chomp( user_pass[0] );
  password = chomp( user_pass[1] );

  if( smbLogin == "Guest" && ( guest_empty || guest_all ) )
    continue;

  if( tolower( password ) == "none" )
    password = "";

  login_defined = remote_login( smbLogin:smbLogin, passwd:password, smbDomain:"", smbName:smbName, smbPort:smbPort );
  if( login_defined ) {
    report = string( "It was possible to login with the following credentials via the SMB protocol to the 'IPC$' share. <User>:<Password>\n\n", smbLogin, ":", password );
    security_message( data:report, port:smbPort );
  }
}

exit( 0 );
