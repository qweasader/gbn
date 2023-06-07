# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.114071");
  script_version("2023-03-01T10:20:05+0000");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:05 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2019-02-13 15:22:06 +0100 (Wed, 13 Feb 2019)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("Beward IP Camera Default Credentials / Unprotected Web Access (HTTP)");
  script_dependencies("gb_beward_ip_camera_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("beward/ip_camera/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"http://prometei-sb.ru/default-login-password/");

  script_tag(name:"summary", value:"The remote installation of Beward's IP camera software is using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Beward's IP camera software is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to Beward's IP camera software is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access or enable password protection.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

CPE = "cpe:/h:beward";

if(!info = get_app_port_from_cpe_prefix(cpe: CPE, service: "www"))
  exit(0);

CPE = info["cpe"];
port = info["port"];

if(!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

creds = make_array("admin", "admin");

host = http_host_name( dont_add_port:TRUE );
url = "/information.htm";
res = http_get_cache(port: port, item: url);

# nb: Some devices are not protected at all.
if(res && res =~ "^HTTP/1\.[01] 401" ) {

  # nb: Used by e.g. default_http_auth_credentials.nasl
  set_kb_item( name:"www/content/auth_required", value:TRUE );
  set_kb_item( name:"www/" + host + "/" + port + "/content/auth_required", value:url );

  report = "It was possible to login with the following default credentials: (username:password)";

  foreach username(keys(creds)) {

    password = creds[username];

    req = http_get_req(port: port, url: url, add_headers: make_array("Accept-Encoding", "gzip, deflate",
                                                                   "Authorization", "Basic " + base64(str: username + ":" + password)));
    res = http_keepalive_send_recv(port: port, data: req);

    if(res && "General.Network.PPPoE.Enabled&group=" >< res && "var onloadFun" >< res) {
      VULN = TRUE;
      report += '\n' + username + ':' + password;
      #Remember any working credentials for other authenticated vulnerability tests
      set_kb_item(name: "beward/ip_camera/credentials", value: username + ":" + password);
    }
  }
} else {
  if(res && "General.Network.PPPoE.Enabled&group=" >< res && "var onloadFun" >< res) {
    report = "The device has no password protection enabled.";
    set_kb_item(name: "beward/ip_camera/credentials", value: ":");
    VULN = TRUE;
  }
}

if(VULN) {
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
