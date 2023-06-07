# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105776");
  script_version("2021-07-01T08:13:06+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-07-01 08:13:06 +0000 (Thu, 01 Jul 2021)");
  script_tag(name:"creation_date", value:"2016-06-22 11:05:14 +0200 (Wed, 22 Jun 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Veeam Backup & Replication Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Veeam Backup & Replication");

  script_xref(name:"URL", value:"https://www.veeam.com/vm-backup-recovery-replication-software.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:9443 );

url = "/login.aspx";
buf = http_get_cache( item:url, port:port );

if ( "Veeam Backup Enterprise Manager : Login" >!< buf &&
     ( "Veeam.CredentialsPanel" >!< buf || "LoginConfig" >!< buf ) )
  exit ( 0 );

cpe = "cpe:/a:veeam:backup_and_replication";

set_kb_item( name:"veeam_backup_and_replication/detected", value:TRUE );
set_kb_item( name:"veeam_backup_and_replication/http/detected", value:TRUE );

version = "unknown";

# favicon.ico?v=11.0.0
# /app.min.js?v=8.0.0.0
vers = eregmatch( pattern:'\\.(css|js|ico)\\?v=([0-9.]+[^"]+)"', string:buf );
if ( ! isnull ( vers[2] ) ) {
  version = vers[2];
  cpe += ":" + version;
}

register_product( cpe:cpe, location:"/", port:port, service:"www" );

log_message( data:build_detection_report( app:"Veeam Backup & Replication", version:version, install:"/",
                                          cpe:cpe, concluded:vers[0] ),
             port:port );
exit( 0 );
