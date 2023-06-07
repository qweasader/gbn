###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Db2 SYSIBMADM Multiple Vulnerabilities (Sep10)
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
  script_oid("1.3.6.1.4.1.25623.1.0.801504");
  script_version("2021-08-10T15:24:26+0000");
  script_tag(name:"last_modification", value:"2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)");
  script_tag(name:"creation_date", value:"2010-09-03 15:47:26 +0200 (Fri, 03 Sep 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2010-3196", "CVE-2010-3197");

  script_name("IBM Db2 SYSIBMADM Multiple Vulnerabilities (Sep10)");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC67008");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21432298");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC67819");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl");
  script_mandatory_keys("ibm/db2/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass security
  restrictions, gain knowledge of sensitive information or cause a denial of service.");

  script_tag(name:"affected", value:"IBM Db2 versions prior to 9.7 Fix Pack 2.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An erron in the handling of 'SYSIBMADM' schema. It does not perform the
    expected access control on the monitor administrative, which allows
    attackers to obtain sensitive information via unspecified vectors.

  - An erron in the handling of 'AUTO_REVAL' when AUTO_REVAL is IMMEDIATE,
    which allows remote authenticated users to cause a denial of service.");

  script_tag(name:"solution", value:"Update Db2 version 9.7 Fix Pack 2.");

  script_tag(name:"summary", value:"IBM DB2 is prone to multiple vulnerabilities.");

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

exit(99);
