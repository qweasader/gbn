###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Db2 'REPEAT()' Heap Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.800448");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-02-04 12:53:38 +0100 (Thu, 04 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2010-0462");

  script_name("IBM Db2 'REPEAT()' Heap Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ibm/db2/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55899");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37976");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Jan/1023509.html");
  script_xref(name:"URL", value:"http://intevydis.blogspot.com/2010/01/ibm-db2-97-heap-overflow.html");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  code with elevated privileges or crash the affected application.");

  script_tag(name:"affected", value:"IBM Db2 version 9.1 before FP9, 9.5 before FP6, 9.7 before FP2.");

  script_tag(name:"insight", value:"The flaw is due to error in 'REPEAT()' function when processing
  SELECT statement that has a long column name generated.");

  script_tag(name:"solution", value:"Upgrade to IBM Db2 version 9.1 FP9 or 9.5 FP6 or 9.7 FP2 or later.");

  script_tag(name:"summary", value:"IBM Db2 and is prone to a buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.1.0.0", test_version2: "9.1.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.0.9");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.5.0.0", test_version2: "9.5.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.0.6");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.7.0.0", test_version2: "9.7.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.7.0.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
