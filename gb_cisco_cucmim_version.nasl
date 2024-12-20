# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105544");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-02-12 12:35:56 +0100 (Fri, 12 Feb 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cisco Unified Communications Manager IM and Presence Detect");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco/cucmim/detected");

  script_tag(name:"summary", value:"This script performs ssh based detection of Cisco Unified Communications Manager IM and Presence");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}


include("host_details.inc");
include("os_func.inc");
include("ssh_func.inc");

if( ! get_kb_item( "cisco/cucmim/detected" ) ) exit( 0 );

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

show_ver = ssh_cmd( socket:sock, cmd:'show version active', nosh:TRUE, pty:TRUE, timeout:60, retry:30, pattern:"Active Master Version:" );

if( ! show_ver || "Active Master Version:" >!< show_ver ) exit( 0 );

cpe = 'cpe:/a:cisco:unified_communications_manager_im_and_presence_service';
ucos_cpe = 'cpe:/o:cisco:ucos';

vers = 'unknown';

version = eregmatch( pattern:'Active Master Version: ([^\r\n]+)', string:show_ver );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  set_kb_item( name:'cisco/cucmim/version', value:vers );
  cpe += ':' + vers;
  ucos_cpe += ':' + vers;
}

register_product( cpe:cpe, location:'ssh' );

os_register_and_report( os:"Cisco UCOS", cpe:ucos_cpe, banner_type:"SSH login", desc:"Cisco Unified Communications Manager IM and Presence Detect", runs_key:"unixoide" );

log_message( data: build_detection_report( app:'Cisco Unified Communications Manager IM and Presence',
                                           version:vers,
                                           install:'ssh',
                                           cpe:cpe,
                                           concluded: 'show version active' ),
             port:0 );

exit( 0 );

