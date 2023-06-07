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

CPE = "cpe:/a:fortinet:fortimail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805646");
  script_version("2022-04-14T06:42:08+0000");
  script_cve_id("CVE-2014-8617");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-14 06:42:08 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2015-06-08 11:54:11 +0530 (Mon, 08 Jun 2015)");
  script_tag(name:"qod_type", value:"package");

  script_name("Fortinet FortiMail Stored XSS Vulnerability (FG-IR-15-005)");

  script_tag(name:"summary", value:"Fortinet FortiMail is prone to a stored cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the Web Action
  Quarantine Release feature does not validate input before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to create a specially crafted request that would execute
  arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server.");

  script_tag(name:"affected", value:"Fortinet FortiMail versions before 4.3.9,
  5.0.x before 5.0.8, 5.1.x before 5.1.5, and 5.2.x before 5.2.3.");

  script_tag(name:"solution", value:"Update to Fortinet FortiMail 4.3.9 or
  5.0.8 or 5.1.5 or 5.2.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-15-005");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72820");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortimail_consolidation.nasl");
  script_mandatory_keys("fortinet/fortimail/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE, nofork: TRUE))
  exit(0);

if(version_is_less(version:version, test_version:"4.3.9")) {
  fix = "4.3.9";
  VULN = TRUE;
}

if(version_in_range(version:version, test_version:"5.0", test_version2:"5.0.7")) {
  fix = "5.0.8";
  VULN = TRUE;
}

if(version_in_range(version:version, test_version:"5.1", test_version2:"5.1.4")) {
  fix = "5.1.5";
  VULN = TRUE;
}

if(version_in_range(version:version, test_version:"5.2", test_version2:"5.2.2")) {
  fix = "5.2.3";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
