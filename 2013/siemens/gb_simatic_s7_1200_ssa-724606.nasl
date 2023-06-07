# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:siemens:simatic_s7_1200";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803387");
  script_version("2022-04-27T04:20:28+0000");
  script_cve_id("CVE-2013-0700", "CVE-2013-2780");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 04:20:28 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-04-25 16:01:27 +0530 (Thu, 25 Apr 2013)");
  script_name("Siemens SIMATIC S7-1200 Multiple DoS Vulnerabilities (SSA-724606)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_siemens_simatic_s7_consolidation.nasl");
  script_mandatory_keys("siemens/simatic_s7/detected");

  script_xref(name:"URL", value:"http://www.siemens.com/corporate-technology/pool/de/forschungsfelder/siemens_security_advisory_ssa-724606.pdf");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57023");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59399");

  script_tag(name:"summary", value:"Siemens SIMATIC S7-1200 devices are prone to multiple denial of
  service (DoS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause DoS
  conditions via specially-crafted packets to TCP port 102 or UCP port 161.");

  script_tag(name:"affected", value:"Siemens SIMATIC S7-1200 versions 2.x and 3.x.");

  script_tag(name:"solution", value:"Update to version 4.0.0 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if(version =~ "^[23]\.") {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
