###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Db2 'db2diag.log' Information Disclosure Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811694");
  script_version("2022-04-13T11:57:07+0000");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-09-14 13:39:29 +0530 (Thu, 14 Sep 2017)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-20 18:47:00 +0000 (Wed, 20 Sep 2017)");

  script_cve_id("CVE-2017-1434");

  script_name("IBM Db2 'db2diag.log' Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"IBM Db2 is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when a version check to upgrade Db2 to v11.x fails, the
  connection string is written in the clear in an error message to db2diag.log.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users to obtain sensitive information.");

  script_tag(name:"affected", value:"IBM DB2 version 11.1.2.2 before 11.1.2.2 FP2");

  script_tag(name:"solution", value:"Upgrade to IBM DB2 version 11.1.2.2 FP2");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22005740");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100693");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl");
  script_mandatory_keys("ibm/db2/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_equal(version: version, test_version: "11.1.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.1.2.2 FP2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
