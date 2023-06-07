###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Db2 Multiple Vulnerabilities (Sep10)
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
  script_oid("1.3.6.1.4.1.25623.1.0.801503");
  script_version("2021-08-10T15:24:26+0000");
  script_tag(name:"last_modification", value:"2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)");
  script_tag(name:"creation_date", value:"2010-09-03 15:47:26 +0200 (Fri, 03 Sep 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2010-3193", "CVE-2010-3194");

  script_name("IBM Db2 Multiple Vulnerabilities (Sep10)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41218");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61445");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2225");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21432298");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21426108");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl");
  script_mandatory_keys("ibm/db2/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass security
  restrictions, gain knowledge of sensitive information or cause a denial of service.");

  script_tag(name:"affected", value:"IBM Db2 versions prior to 9.1 Fix Pack 9, IBM Db2 versions prior to
  9.5 Fix Pack 6 and IBM Db2 versions prior to 9.7 Fix Pack 2.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An unspecified error related to 'DB2STST' program, which has unknown impact and attack vectors.

  - An error related to 'DB2DART' program, which could be exploited to overwrite files owned by the instance owner.");

  script_tag(name:"solution", value:"Update Db2 9.1 Fix Pack 9, 9.5 Fix Pack 6, or 9.7 Fix Pack 2.");

  script_tag(name:"summary", value:"IBM DB2 and is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.7.0.0", test_version2: "9.7.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.7.0.2");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.5.0.0", test_version2: "9.5.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.0.6");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.1.0.0", test_version2: "9.1.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.0.9");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
