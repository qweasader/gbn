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

CPE = "cpe:/a:apache:solr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903507");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2013-6408");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-01-29 16:29:04 +0530 (Wed, 29 Jan 2014)");
  script_name("Apache Solr XML External Entity (XXE) Vulnerability (SOLR-4881, SOLR-5520) (Linux)");

  script_tag(name:"summary", value:"Apache Solr is prone to an XML external entity (XXE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error in 'DocumentAnalysisRequestHandler' when parsing XML
  entities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain potentially
  sensitive information and potentially perform other more advanced XXE attacks.");

  script_tag(name:"affected", value:"Apache Solr versions before 3.6.3 and 4.x before 4.3.1.");

  script_tag(name:"solution", value:"Update to version 3.6.3, 4.3.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55542");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64009");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/11/29/2");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/SOLR-4881");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/SOLR-5520");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_apache_solr_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/solr/detected", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.6.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.3, 4.3.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

else if (version =~ "^4\.[0-3]" && version_is_less(version: version, test_version: "4.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
