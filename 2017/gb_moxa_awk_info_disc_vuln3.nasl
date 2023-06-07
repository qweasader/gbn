###############################################################################
# OpenVAS Vulnerability Test
#
# Moxa AWK Series asqc.asp Information Disclosure Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/h:moxa";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106743");
  script_version("2022-12-16T10:18:13+0000");
  script_tag(name:"last_modification", value:"2022-12-16 10:18:13 +0000 (Fri, 16 Dec 2022)");
  script_tag(name:"creation_date", value:"2017-04-12 08:26:22 +0200 (Wed, 12 Apr 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-14 13:43:00 +0000 (Wed, 14 Dec 2022)");

  script_cve_id("CVE-2016-8722");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moxa AWK Series asqc.asp Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moxa_awk_detect.nasl");
  script_mandatory_keys("moxa_awk/detected");

  script_tag(name:"summary", value:"Moxa AWK series wireless access points are prone to an information
  disclosure vulnerability .");

  script_tag(name:"vuldetect", value:"Sends a HTTP request and checks the response.");

  script_tag(name:"insight", value:"Retrieving a specific URL, /asqc.asp, without authentication can reveal
  sensitive information to an attacker.");

  script_tag(name:"impact", value:"An unauthenticated attacker may obtain sensitive information.");

  script_tag(name:"solution", value:"Update to version 1.4 or later.");

  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2016-0236/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
CPE = infos["cpe"];

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/asqc.asp";

if (http_vuln_check(port: port, url: url, pattern: "System Info", extra_check: "BIOS version",
                    check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
