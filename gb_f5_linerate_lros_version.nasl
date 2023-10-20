# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105304");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-06-24 13:13:10 +0200 (Wed, 24 Jun 2015)");
  script_name("F5 LineRate LROS Detection");

  script_tag(name:"summary", value:"This script performs SSH based detection of F5 LineRate LROS");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("f5/LROS/show_version");
  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

infos = get_kb_item( "f5/LROS/show_version" );

if( "F5 Networks LROS" >!< infos ) exit( 0 );

cpe = 'cpe:/a:f5:linerate';
vers = 'unknown';

version = eregmatch( pattern:'F5 Networks LROS Version ([0-9.]+[^\r\n ]+)', string:infos );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
}

register_product( cpe:cpe, location:'ssh' );

report = 'Detected F5 LineRate LROS  (ssh)\n' +
         'Version: ' + vers + '\n';

log_message( port:0, data: report );
exit( 0 );

