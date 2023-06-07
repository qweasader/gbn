# Copyright (C) 2012 Greenbone Networks GmbH
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

CPE = "cpe:/a:sonexis:conferencemanager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103420");
  script_version("2023-01-05T10:12:14+0000");
  script_tag(name:"last_modification", value:"2023-01-05 10:12:14 +0000 (Thu, 05 Jan 2023)");
  script_tag(name:"creation_date", value:"2012-02-15 10:59:59 +0100 (Wed, 15 Feb 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sonexis ConferenceManager <= 10.0.40 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sonesix_conference_manager_http_detect.nasl");
  script_mandatory_keys("compunetics/conference_manager/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Sonexis ConferenceManager is prone to an information disclosure
  a security-bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker may exploit these issues to obtain sensitive
  information and bypass certain security restrictions.");

  script_tag(name:"affected", value:"Sonexis ConferenceManager version 10.0.40 and prior.");

  script_tag(name:"solution", value:"Reportedly, the issue is fixed, however, Symantec has not
  confirmed this. Please contact the vendor for more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51994");
  script_xref(name:"URL", value:"http://pentest.snosoft.com/2012/02/13/netragard-uncovers-0-days-in-sonexis-conferencemanager/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/admin/backup/settings.asp";

if (http_vuln_check(port: port, url: url, pattern: "External Location for Download",
                    extra_check: make_list("User ID:", "Password:", "<Title>Upload"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
