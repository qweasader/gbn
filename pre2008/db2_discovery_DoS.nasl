# OpenVAS Vulnerability Test
# Description: Db2 discovery service DOS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11896");
  script_version("2020-03-13T07:09:19+0000");
  script_tag(name:"last_modification", value:"2020-03-13 07:09:19 +0000 (Fri, 13 Mar 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2003-0827");

  script_name("Db2 discovery service DOS");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl");
  script_mandatory_keys("ibm/db2/detected");

  script_tag(name:"solution", value:"Apply 7.2 FixPack 10a or later.");

  script_tag(name:"summary", value:"It was possible to crash the DB2 UDP based discovery service
  by sending a too long packet.");

  script_tag(name:"impact", value:"An attacker  may use this attack to make this service crash
  continuously, preventing you from working properly.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "7.1.0.0", test_version2: "7.2.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.0.10a");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
