# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105303");
  script_version("2024-03-04T05:10:24+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-03-04 05:10:24 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-06-23 14:39:15 +0200 (Tue, 23 Jun 2015)");
  script_name("F5 Networks Enterprise Manager Detection (SSH Login)");

  script_tag(name:"summary", value:"SSH login-based detection of the F5 Networks Enterprise Manager.");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("f5/f5_enterprise_manager/VERSION_RAW");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("version_func.inc");
include("os_func.inc");

SCRIPT_DESC = "F5 Networks Enterprise Manager Detection (SSH Login)";

infos = get_kb_item( "f5/f5_enterprise_manager/VERSION_RAW" );
if( "Product: EM" >!< infos )
  exit( 0 );

set_kb_item( name:"f5/enterprise_manager/detected", value:TRUE );

if( get_kb_item("f5/shell_is_tmsh") )
  nosh = TRUE;

_version = "unknown";
_build = "unknown";
_hotfix = 0;

version = eregmatch( pattern:'Version: ([^\r\n]+)', string:infos );
build   = eregmatch( pattern:'Build: ([^\r\n]+)', string:infos );
built   = eregmatch( pattern:'Built: ([^\r\n]+)', string:infos );
edition = eregmatch( pattern:'Edition: ([^\r\n]+)', string:infos );
hotfix  = eregmatch( pattern:'Edition:.*Hotfix HF([^\r\n]+)', string:infos );
changelist = eregmatch( pattern:'Changelist: ([^\r\n]+)', string:infos );

if( ! isnull( version[1] ) ) {
  _version = version[1];
  set_kb_item( name:"f5/f5_enterprise_manager/version", value:_version );
}

if( ! isnull( build[1] ) ) {
  _build = build[1];
  set_kb_item( name:"f5/f5_enterprise_manager/build", value:_build );
}

if( ! isnull( hotfix[1] ) )
  _hotfix = hotfix[1];

set_kb_item( name:"f5/f5_enterprise_manager/hotfix", value:_hotfix );

if( ! isnull( edition[1] ) )
  set_kb_item( name:"f5/f5_enterprise_manager/edition", value:edition[1] );

if( ! isnull( built[1] ) )
  set_kb_item( name:"f5/f5_enterprise_manager/built", value:built[1] );

if( ! isnull( changelist[1] ) )
  set_kb_item( name:"f5/f5_enterprise_manager/changelist", value:changelist[1] );

if( nosh )
  modules_cmd = ssh_cmd_exec( cmd:"list sys provision", nosh:TRUE );
else
  modules_cmd = ssh_cmd_exec( cmd:"tmsh list sys provision" );

if( ! isnull( modules_cmd ) ) {
  modules_lines = split( modules_cmd );
  for( i = 0; i < max_index( modules_lines ); i++ ) {
    if( "{ }" >< modules_lines[i] )
      continue;
    if( module = eregmatch( pattern:'sys provision ([^ \r\n{]+) \\{[\r\n]+', string:modules_lines[i] ) )
      active_modules += module[1] + ",";
  }
}

if( active_modules =~ ",$" )
  active_modules = ereg_replace( pattern:"(,)$", replace:"", string:active_modules );
active_modules = toupper( active_modules );

if( active_modules )
  set_kb_item( name:"f5/f5_enterprise_manager/active_modules", value:active_modules );

cpe = "cpe:/a:f5:enterprise_manager";

if( _version != "unknown" )
  cpe += ":" + _version;

register_product( cpe:cpe, location:"ssh" );

report = 'Detected F5 Enterprise Manager (ssh)\n' +
         'Version: ' + _version + ' (HF' + _hotfix + ')\n' +
         'Build: ' + _build + '\n';

if( active_modules )
  report += 'Modules: ' + active_modules + '\n';

# From https://my.f5.com/manage/s/article/K7545:
# 3.0.0 - 3.1.1 -> CentOS 5.4 - 6.0
# 2.0.0 - 2.3.0 -> CentOS 5.4
if( version_in_range( version:_version, test_version:"2.0.0", test_version2:"2.3.0" ) )
  os_register_and_report( os:"CentOS", version:"5.4", cpe:"cpe:/o:centos:centos", desc:SCRIPT_DESC, runs_key:"unixoide" );
else if( version_in_range( version:_version, test_version:"3.0.0", test_version2:"3.1.1" ) )
  os_register_and_report( os:"CentOS", version:"6.0", cpe:"cpe:/o:centos:centos", desc:SCRIPT_DESC, runs_key:"unixoide" );
else
  os_register_and_report( os:"CentOS", cpe:"cpe:/o:centos:centos", desc:SCRIPT_DESC, runs_key:"unixoide" );

log_message( port:0, data:report );
exit( 0 );
