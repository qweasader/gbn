# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105266");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-05-08 14:52:31 +0200 (Fri, 08 May 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Juniper ScreenOS Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ScreenOS/detected");

  script_tag(name:"summary", value:"This script performs SSH based detection of Juniper ScreenOS");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("os_func.inc");

if( ! get_kb_item("ScreenOS/detected") ) exit( 0 );

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

system = ssh_cmd( socket:sock, cmd:'get system', nosh:TRUE, pty:TRUE, pattern:"Software Version: " );

if("Product Name:" >!< system || "FPGA checksum" >!< system || "Compiled by build_master at" >!< system || "File Name:" >!< system ) exit( 0 );

set_kb_item( name:"ScreenOS/system", value:system );

vers = 'unknown';
cpe = 'cpe:/o:juniper:screenos';

version = eregmatch( pattern:'Software Version: ([^,]+)', string:system ); # for example 6.2.0r18.0 so take care of the "r" in version checks. E.g. just replace "r" with a dot

if( ! isnull( version[1] ) )
{
  vers = version[1];
  set_kb_item( name:"ScreenOS/version", value:vers );
  cpe += ':' + vers;
}

type = eregmatch( pattern:'Software Version: [^,]+, Type: ([^\r\n]+)', string:system );

if( ! isnull( type[1] ) )
{
   t = type[1];
   set_kb_item( name:"ScreenOS/type", value:t );
}

register_product( cpe:cpe, location:'ssh' );

os_register_and_report( os:"Juniper ScreenOS", cpe:cpe, banner_type:"SSH login", desc:"Juniper ScreenOS Detection", runs_key:"unixoide" );

report = 'Detected Juniper ScreenOS (ssh)\n\n' +
         'Version: ' + vers + '\n';

if( type )
  report += 'Type:    ' + t + '\n';

report += 'CPE:     ' + cpe;

log_message( port:0, data:report );

exit( 0 );

