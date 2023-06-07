# Copyright (C) 2009 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101106");
  script_version("2021-09-01T12:57:33+0000");
  script_tag(name:"last_modification", value:"2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-08-24 07:49:31 +0200 (Mon, 24 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2009-2859", "CVE-2009-2860");

  script_name("IBM Db2 Multiple Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ibm/db2/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2293");
  script_xref(name:"URL", value:"ftp://ftp.software.ibm.com/ps/products/db2/fixes/english-us/aparlist/db2_v82/APARLIST.TXT");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24024075");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of service or
  compromise a vulnerable system.");

  script_tag(name:"affected", value:"IBM Db2 version 8.1 prior to Fixpak 18.");

  script_tag(name:"insight", value:"The flaws are due to:

  - An unspecified error when using DAS command may allow attackers to gain
    unauthorized access to a vulnerable database.

  - An unspecified error when processing malformed packets can be exploited
    to cause DB2JDS to crash creating a denial of service condition.");

  script_tag(name:"solution", value:"Update IBM Db2 Version 8.1 Fixpak 18.");

  script_tag(name:"summary", value:"IBM Db2 is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:ibm:db2";

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "8.1.0", test_version2: "8.1.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.18");
  security_message(data: report, port: 0);
  exit(0);
}

exit(99);
