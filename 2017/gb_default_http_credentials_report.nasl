# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103240");
  script_version("2022-08-04T13:37:02+0000");
  script_cve_id("CVE-1999-0501", "CVE-1999-0502", "CVE-1999-0507", "CVE-1999-0508");
  script_tag(name:"last_modification", value:"2022-08-04 13:37:02 +0000 (Thu, 04 Aug 2022)");
  script_tag(name:"creation_date", value:"2017-01-06 13:47:00 +0100 (Fri, 06 Jan 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("HTTP Brute Force Logins With Default Credentials Reporting");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Brute force attacks");
  script_dependencies("default_http_auth_credentials.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("default_http_auth_credentials/started");

  # nb: This VT had a script preference with the id:1, newly added preferences in the future needs to
  # choose id:2 or higher to avoid conflicts with that removed preference still kept in gvmd database.

  script_tag(name:"summary", value:"It was possible to login into the remote Web Application using
  default credentials.");

  script_tag(name:"vuldetect", value:"Reports default credentials detected by the VT
  'HTTP Brute Force Logins With Default Credentials' (OID: 1.3.6.1.4.1.25623.1.0.108041).");

  script_tag(name:"insight", value:"As the VT 'HTTP Brute Force Logins With Default Credentials'
  (OID: 1.3.6.1.4.1.25623.1.0.108041) might run into a timeout the actual reporting of this
  vulnerability takes place in this VT instead.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to e.g. gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Change the password as soon as possible.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

credentials = get_kb_list( "default_http_auth_credentials/" + host + "/" + port + "/credentials" );
if( ! isnull( credentials ) ) {

  report = 'It was possible to login with the following credentials (<URL>:<User>:<Password>:<HTTP status code>)\n\n';

  # Sort to not report changes on delta reports if just the order is different
  credentials = sort( credentials );

  foreach credential( credentials ) {
    url_user_pass = split( credential, sep:"#-----#", keep:FALSE );
    report += http_report_vuln_url( port:port, url:url_user_pass[0], url_only:TRUE ) + ":" + url_user_pass[1] + '\n';
    vuln = TRUE;
  }
}

if( vuln ) {
  count = get_kb_item( "default_http_auth_credentials/" + host + "/" + port + "/too_many_logins" );
  if( count ) {
    report += '\nRemote host accept more than ' + count + ' logins. This could indicate some error or some "broken" web application.\nScanner stops testing for default logins at this point.';
    log_message( port:port, data:report );
    exit( 0 );
  }
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
