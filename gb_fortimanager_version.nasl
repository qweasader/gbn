###############################################################################
# OpenVAS Vulnerability Test
#
# FortiManager Detection
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105814");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2022-03-16T13:03:04+0000");
  script_tag(name:"last_modification", value:"2022-03-16 13:03:04 +0000 (Wed, 16 Mar 2022)");
  script_tag(name:"creation_date", value:"2016-07-19 09:58:46 +0200 (Tue, 19 Jul 2016)");
  script_name("FortiManager Detection (SSH Login)");

  script_tag(name:"summary", value:"SSH login-based detection of FortiManager.");
  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("fortinet/fortios/system_status");
  exit(0);
}

include("host_details.inc");

system = get_kb_item( "fortinet/fortios/system_status" );
if( ! system || "FortiManager" >!< system )
  exit( 0 );

cpe = "cpe:/h:fortinet:fortimanager";
vers = "unknown";

m = eregmatch( pattern:'Platform Full Name\\s*:\\s*FortiManager-([^ \r\n]+)', string:system );
if( ! isnull( m[1] ) ) {
  model = m[1];
  set_kb_item( name:"fortimanager/model", value:model );
}

if( version = get_kb_item( "forti/FortiOS/version" ) ) {
  vers = version;
  cpe += ":" + vers;
  set_kb_item( name:"fortimanager/version", value:TRUE );
}

rep_vers = vers;

if( build = get_kb_item( "forti/FortiOS/build" ) ) {
  set_kb_item( name:"fortimanager/build", value:build );
  rep_vers += " Build " + build;
}

register_product( cpe:cpe, location:"ssh", service:"ssh" );

report = build_detection_report( app:"FortiManager", version:rep_vers, install:"ssh", cpe:cpe, concluded:system );
log_message( port:0, data:report );
exit( 0 );
