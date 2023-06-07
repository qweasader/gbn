# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:openldap:openldap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148063");
  script_version("2022-05-16T03:04:21+0000");
  script_tag(name:"last_modification", value:"2022-05-16 03:04:21 +0000 (Mon, 16 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-05 09:47:51 +0000 (Thu, 05 May 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-12 19:22:00 +0000 (Thu, 12 May 2022)");

  script_cve_id("CVE-2022-29155");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenLDAP SQLi Vulnerability (May 2022)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openldap_consolidation.nasl");
  script_mandatory_keys("openldap/detected");

  script_tag(name:"summary", value:"OpenLDAP is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An SQL injection vulnerability exists in the experimental
  back-sql backend to slapd, via a SQL statement within an LDAP query. This can occur during an
  LDAP search operation when the search filter is processed, due to a lack of proper escaping.");

  script_tag(name:"affected", value:"OpenLDAP version 2.5.11 and prior and 2.6.x through 2.6.1.");

  script_tag(name:"solution", value:"Update to version 2.5.12, 2.6.2 or later.");

  script_xref(name:"URL", value:"https://bugs.openldap.org/show_bug.cgi?id=9815");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "2.5.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.6.0", test_version_up: "2.6.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.6.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
