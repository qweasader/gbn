# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108815");
  script_version("2021-08-11T08:56:08+0000");
  script_tag(name:"last_modification", value:"2021-08-11 08:56:08 +0000 (Wed, 11 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-07-06 05:44:03 +0000 (Mon, 06 Jul 2020)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-02 16:15:00 +0000 (Fri, 02 Apr 2021)");

  script_cve_id("CVE-2020-10730", "CVE-2020-10760");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Samba Multiple Use-after-free Vulnerabilities (CVE-2020-10730, CVE-2020-10760)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"summary", value:"Samba is prone to two use-after-free vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- A client combining the 'ASQ' and 'VLV' LDAP controls can cause
  a NULL pointer de-reference and further combinations with the LDAP paged_results feature can give
  a use-after-free in Samba's AD DC LDAP server. (CVE-2020-10730)

  - The use of the paged_results or VLV controls against the Global Catalog LDAP server on the AD DC
  will cause a use-after-free. (CVE-2020-10760)");

  script_tag(name:"affected", value:"All Samba versions since 4.5.0.");

  script_tag(name:"solution", value:"Update to version 4.10.17, 4.11.11, 4.12.4 or later.");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2020-10730.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2020-10760.html");

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

if (version_in_range(version: version, test_version: "4.5.0", test_version2: "4.10.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.10.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.11.0", test_version2: "4.11.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.11.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.12.0", test_version2: "4.12.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.12.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
