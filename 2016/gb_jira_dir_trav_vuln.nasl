###############################################################################
# OpenVAS Vulnerability Test
#
# Atlassian JIRA Directory Traversal Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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

CPE = "cpe:/a:atlassian:jira";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106154");
  script_version("2021-10-08T12:48:53+0000");
  script_tag(name:"last_modification", value:"2021-10-08 12:48:53 +0000 (Fri, 08 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-07-27 15:23:00 +0700 (Wed, 27 Jul 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_cve_id("CVE-2014-2313", "CVE-2014-2314");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atlassian JIRA < 6.0.5 Directory Traversal Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_jira_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("atlassian/jira/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Atlassian JIRA is prone to two directory traversal vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Atlassian JIRA is prone to two directory traversal vulnerabilities:

Directory traversal vulnerability in the Importers plugin allows remote attackers to create arbitrary files
via unspecified vectors. (CVE-2014-2313)

Directory traversal vulnerability in the Issue Collector plugin allows remote attackers to create arbitrary
files via unspecified vectors. (CVE-2014-2314)");

  script_tag(name:"impact", value:"An unauthenticated remote attacker may upload arbitrary files.");

  script_tag(name:"affected", value:"Versions prior to 6.0.5 on Windows.");

  script_tag(name:"solution", value:"Update to version 6.0.5 or later.");

  script_xref(name:"URL", value:"http://blog.h3xstream.com/2014/02/jira-path-traversal-explained.html");
  script_xref(name:"URL", value:"https://confluence.atlassian.com/jira/jira-security-advisory-2014-02-26-445188412.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "6.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
