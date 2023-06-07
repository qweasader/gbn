# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:subversion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805607");
  script_version("2022-06-03T07:48:46+0000");
  script_tag(name:"last_modification", value:"2022-06-03 07:48:46 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2015-05-06 12:54:14 +0530 (Wed, 06 May 2015)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2015-0202");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Subversion 1.8.x DoS Vulnerability (May 2015)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_apache_subversion_detect.nasl");
  script_mandatory_keys("apache/subversion/detected");

  script_tag(name:"summary", value:"Apache Subversion is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to vulnerability in mod_dav_svn that is
  triggered during the handling of certain REPORT requests, which can cause elements to be
  repeatedly allocated from a memory pool without being properly deallocated.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to use
  multiple concurrent REPORT requests to exhaust all available memory on the system.");

  script_tag(name:"affected", value:"Subversion version 1.8.0 through 1.8.11.");

  script_tag(name:"solution", value:"Update to version 1.8.13 or later.");

  script_xref(name:"URL", value:"http://subversion.apache.org/security/CVE-2015-0202-advisory.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.8.0", test_version2: "1.8.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.13");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);