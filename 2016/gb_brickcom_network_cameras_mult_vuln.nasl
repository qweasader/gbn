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

CPE_PREFIX = "cpe:/h:brickcom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808159");
  script_version("2023-01-12T10:12:15+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-01-12 10:12:15 +0000 (Thu, 12 Jan 2023)");
  script_tag(name:"creation_date", value:"2016-06-10 17:32:08 +0530 (Fri, 10 Jun 2016)");
  script_name("Brickcom Network Cameras Multiple Vulnerabilities (Dec 2015)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_brickcom_network_camera_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("brickcom/network_camera/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/136693/OLSA-2015-12-12.txt");

  script_tag(name:"summary", value:"Brickcom Network Camera devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The flaws exist due to:

  - 'syslog.dump' and 'configfile.dump' files accessible without authentication.

  - Credentials and other sensitive information are stored in plain text.

  - The usage of defaults credentials like 'admin:admin', 'viewer:viewer', 'rviewer:rviewer'.

  - An improper input validation for parameter 'action' to the 'NotificationTest.cgi' script leading
  to a cross-site scripting (XSS) vulnerability

  - A cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to access sensitive
  information stored in HTML pages, gain administrative access, execute XSS and CSRF attacks.");

  script_tag(name:"affected", value:"Please see the references for information on affected products
  and firmware versions.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("misc_func.inc");

if(!infos = get_app_port_from_cpe_prefix(cpe:CPE_PREFIX, service:"www"))
  exit(0);

port = infos["port"];
CPE  = infos["cpe"];

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/user_management_config.html";
userpasswds = make_list("admin:admin", "viewer:viewer", "rviewer:rviewer");

host = http_host_name(port:port);

foreach userpass(userpasswds){
  userpass64 = base64(str:userpass);

  req = 'GET ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'Authorization: Basic ' + userpass64 + '\r\n' +
        '\r\n';
  res = http_send_recv(port:port, data:req);

  if(res =~ "^HTTP/1\.[01] 200" && "Brickcom Corporation" >< res &&
     ("<title>User Management</title>" >< res || "Camera Configuration Utility" >< res || "<title>Live View</title>") &&
     (('="viewer"' >< res && '="admin"' >< res && '="rviewer"' >< res) || "viewer=='admin'" >< res)) {
    report = 'Authentication bypass possible using the login and password: ' + userpass + '\n\n';
    report += http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
