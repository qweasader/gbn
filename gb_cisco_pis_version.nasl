###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Prime Infrastructure Version Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105614");
  script_version("2022-05-31T20:54:22+0100");
  script_tag(name:"last_modification", value:"2022-05-31 20:54:22 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2016-04-21 10:11:13 +0200 (Thu, 21 Apr 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cisco Prime Infrastructure Version Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_pis_ssh_detect.nasl", "gb_cisco_pis_web_detect.nasl");
  script_mandatory_keys("cisco/pis/detected");

  script_tag(name:"summary", value:"This Script consolidate the via SSH/HTTP detected version of Cisco Prime Infrastructure");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");

source ="ssh";

if( ! version = get_kb_item( "cisco_pis/" + source + "/version" ) ) {
  source = "http";
  if( ! version = get_kb_item( "cisco_pis/" + source + "/version" ) )
    exit( 0 );
  else
  {
    os_register_and_report( os:"Cisco Application Deployment Engine OS", cpe:"cpe:/o:cisco:application_deployment_engine", banner_type:toupper( source ), desc:"Cisco Prime Infrastructure Version Detection", runs_key:"unixoide" );
  }
}

set_kb_item( name:"cisco_pis/version", value:version );
set_kb_item( name:"cisco_pis/version_source", value:source );

cpe = 'cpe:/a:cisco:prime_infrastructure:' + version;

if( installed_patches = get_kb_item( "cisco_pis/" + source + "/installed_patches" ) )
  set_kb_item( name:"cisco_pis/installed_patches", value:installed_patches );
else
  set_kb_item( name:"cisco_pis/installed_patches", value:"no patches installed" );

if( max_patch_version = get_kb_item( "cisco_pis/" + source + "/max_patch_version" ) )
  set_kb_item( name:"cisco_pis/max_patch_version", value:max_patch_version );

if( build = get_kb_item( "cisco_pis/" + source + "/build" ) )
  set_kb_item( name:"cisco_pis/build", value:build );

register_product( cpe:cpe, location:source );
exit( 0 );

