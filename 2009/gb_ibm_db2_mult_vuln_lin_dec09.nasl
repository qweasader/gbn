###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Db2 Multiple Vulnerabilities - Dec09 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801071");
  script_version("2022-05-31T12:44:43+0100");
  script_tag(name:"last_modification", value:"2022-05-31 12:44:43 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2009-12-05 12:49:16 +0100 (Sat, 05 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2009-4150");

  script_name("IBM Db2 Multiple Vulnerabilities - Dec09 (Linux)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37454");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1023242");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3340");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21386689");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21403619");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg27007053");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ibm/db2/detected", "Host/runs_unixoide");

  script_tag(name:"impact", value:"Successful exploitation allows the attacker to potentially perform certain
  actions with escalated privileges or to bypass certain security restrictions.");

  script_tag(name:"affected", value:"IBM Db2 version 8 prior to Fixpack 18, 9.1 prior to Fixpack 8,
  9.5 prior to Fixpack 4 and 9.7 prior to Fixpack 1.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Unspecified error exists related to a table function when the definer
    loses required privileges.

  - Unspecified error that can be exploited to insert, update, or delete rows
    in a table without having required privileges.

  - Unspecified error in the handling of 'SET SESSION AUTHORIZATION' statements.

  - Error in 'DASAUTO' command, it can be run by non-privileged users.");

  script_tag(name:"solution", value:"Update Db2 8 Fixpak 18, 9.1 Fixpack 8, 9.5 Fixpack 4, 9.7 Fixpack 1 or later.");

  script_tag(name:"summary", value:"IBM Db2 is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.1.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.18");
  security_message(data: report, port: 0);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.1.0.0", test_version2: "9.1.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.0.8");
  security_message(data: report, port: 0);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.5.0.0", test_version2: "9.5.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.0.4");
  security_message(data: report, port: 0);
  exit(0);
}

if (version_is_equal(version: version, test_version: "9.7.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.7.0.1");
  security_message(data: report, port: 0);
  exit(0);
}

exit(99);
