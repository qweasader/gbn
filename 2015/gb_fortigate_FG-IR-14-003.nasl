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

CPE = "cpe:/o:fortinet:fortios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105207");
  script_version("2022-03-17T02:33:02+0000");
  script_tag(name:"last_modification", value:"2022-03-17 02:33:02 +0000 (Thu, 17 Mar 2022)");
  script_tag(name:"creation_date", value:"2015-02-11 12:17:13 +0100 (Wed, 11 Feb 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2013-7182");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiGate XSS Vulnerability (FG-IR-14-003)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortinet_fortigate_consolidation.nasl");
  script_mandatory_keys("fortinet/fortigate/detected");

  script_tag(name:"summary", value:"FortiOS as used in FortiGate is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The mkey parameter in the URL /firewall/schedule/recurrdlg is
  vulnerable to a reflected cross-site scripting attack.");

  script_tag(name:"impact", value:"A remote unauthenticated attacker may be able to execute
  arbitrary script in the context of the end-user's browser session.");

  script_tag(name:"affected", value:"FortiOS 5.0.5 and earlier as uses in FortiGate.");

  script_tag(name:"solution", value:"Update to FortiOS 5.0.6 or later.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-14-003");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!get_kb_item("fortinet/fortigate/detected"))
  exit(0);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "5.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.6");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
