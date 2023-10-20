# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96206");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2011-06-06 16:48:59 +0200 (Mon, 06 Jun 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Report Cisco IOS Software Version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_os_detection.nasl", "gb_cisco_ios_version_ssh.nasl");
  script_mandatory_keys("cisco_ios/detected");

  script_tag(name:"summary", value:"Report the Cisco IOS Software Version.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("os_func.inc");

cpe = "cpe:/o:cisco:ios";
version = "unknown";

source = "ssh";

if( ! version = get_kb_item( "cisco_ios/" + source + "/version" ) )
{
  source = "snmp";
  if( ! version = get_kb_item( "cisco_ios/" + source + "/version" ) ) exit( 0 );
}

if( ! isnull( version ) )
{
  cpe += ":" + version;
  set_kb_item( name:"cisco_ios/version", value:version );
  set_kb_item( name:"SSH/Cisco/Version", value:version ); # nb: for old VTs
}

if( model = get_kb_item( "cisco_ios/" + source + "/model")  )
{
  set_kb_item( name:'cisco_ios/model', value:model );
}

if( image = get_kb_item( "cisco_ios/" + source + "/image")  )
{
  set_kb_item( name:'cisco_ios/image', value:image );
}

register_product( cpe:cpe, location:source );
os_register_and_report( os:"Cisco IOS", cpe:cpe, banner_type:toupper( source ), desc:"Report Cisco IOS Software Version", runs_key:"unixoide" );

report = 'Detected Cisco IOS\n' +
         'Version: ' + version + '\n' +
         'CPE: ' + cpe + '\n';

if( model ) report += 'Model:   ' + model + '\n';
if( image ) report += 'Image:   ' + image + '\n';

report += 'Detection source: ' + source + '\n';

log_message( port:0, data:report );
exit( 0 );
