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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108627");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2014-0050", "CVE-2014-0094");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2019-08-28 07:41:10 +0000 (Wed, 28 Aug 2019)");
  script_name("Apache Struts Security Update (S2-020) - Version Check");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-020");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65400");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65999");
  script_xref(name:"Advisory-ID", value:"S2-020");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-058");
  script_xref(name:"Advisory-ID", value:"S2-058");

  script_tag(name:"summary", value:"Apache Struts is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The default upload mechanism in Apache Struts 2 is
  based on Commons FileUpload version 1.3 which is vulnerable and allows DoS attacks.
  Additional ParametersInterceptor allows access to 'class' parameter which is directly
  mapped to getClass() method and allows ClassLoader manipulation.");

  script_tag(name:"impact", value:"A remote attacker can execute arbitrary Java code via
  crafted parameters or cause a Denial of Service.");

  script_tag(name:"affected", value:"Apache Struts 2.0.0 through 2.3.16.1.");

  script_tag(name:"solution", value:"Update to version 2.3.16.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];

if(version_in_range(version: vers, test_version: "2.0.0", test_version2: "2.3.16.1")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2.3.16.2", install_path: infos["location"]);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
