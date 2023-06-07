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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107240");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-9804");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-09-11 14:24:03 +0200 (Mon, 11 Sep 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_name("Apache Struts Security Update (S2-050)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100612");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-050");
  script_xref(name:"Advisory-ID", value:"S2-050");

  script_tag(name:"summary", value:"Apache Struts is prone to a regular expression Denial
  of Service (DoS) vulnerability when using URLValidator.");

  script_tag(name:"insight", value:"The previous fix issued with S2-047 was incomplete.
  If an application allows enter an URL in a form field and built-in URLValidator is used,
  it is possible to prepare a special URL which will be used to overload server process
  when performing validation of the URL.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause a DoS
  condition, denying service to legitimate users.");

  script_tag(name:"affected", value:"Apache Struts 2.3.7 through 2.3.33 and 2.5 through
  2.5.12.");

  script_tag(name:"solution", value:"Update to version 2.3.34, 2.5.13 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];

if(version_in_range(version: vers, test_version: "2.3.7", test_version2: "2.3.33")) {
  vuln = TRUE;
  fix = "2.3.34";
}

else if(version_in_range(version: vers, test_version: "2.5.0", test_version2: "2.5.12")) {
  vuln = TRUE;
  fix = "2.5.13";
}

if(vuln) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: infos["location"]);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);