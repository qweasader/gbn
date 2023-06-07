# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902489");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-11-08 15:07:48 +0530 (Tue, 08 Nov 2011)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-4061");

  script_name("IBM Db2 'DT_RPATH' Insecure Library Loading Code Execution Vulnerabilities");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl");
  script_mandatory_keys("ibm/db2/detected");

  script_tag(name:"impact", value:"Successful exploitation allows local unauthenticated users to gain elevated
  privileges and execute arbitrary code with root privileges.");

  script_tag(name:"affected", value:"IBM Db2 version 9.7");

  script_tag(name:"insight", value:"The flaws are due to an error in 'db2rspgn' and 'kbbacf1', which allow users
  to gain privileges via a Trojan horse libkbb.so in the current working directory.");

  script_tag(name:"solution", value:"Upgrade to version 9.7 Fix Pack 6, 10.1 Fix Pack 1, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"IBM Db2 is prone to insecure library loading vulnerabilities.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/518659");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48514");
  script_xref(name:"URL", value:"http://www.nth-dimension.org.uk/downloads.php?id=77");
  script_xref(name:"URL", value:"http://www.nth-dimension.org.uk/downloads.php?id=83");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.7.0", test_version2: "9.7.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.7.0.6");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
