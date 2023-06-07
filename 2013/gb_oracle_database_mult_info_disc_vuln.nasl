###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Database Server Multiple Information Disclosure Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE = 'cpe:/a:oracle:database_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803956");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-3826", "CVE-2013-5771");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-10-28 14:27:36 +0530 (Mon, 28 Oct 2013)");
  script_name("Oracle Database Server Multiple Information Disclosure Vulnerabilities");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain potentially sensitive
  information and manipulate certain data.");

  script_tag(name:"affected", value:"Oracle Database Server version 11.1.0.7, 11.2.0.2, 11.2.0.3, and 12.1.0.1
  are affected.");

  script_tag(name:"insight", value:"Multiple flaws exist in Core RDBMS component and XML Parser component, no
  further information available at this moment.");

  script_tag(name:"solution", value:"Apply the updates from the referenced advisories.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"summary", value:"Oracle Database Server is prone to multiple information disclosure vulnerabilities.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55322");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63044");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63046");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2013verbose-1899842.html#DB");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html#AppendixDB");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("oracle_tnslsnr_version.nasl");
  script_mandatory_keys("OracleDatabaseServer/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!ver = get_app_version(cpe:CPE, port:port))exit(0);

if(ver =~ "^(11\.[1|2]\.0|12\.1\.0)")
{
  if(version_in_range(version:ver, test_version:"11.2.0.2", test_version2:"11.2.0.3") ||
     version_is_equal(version:ver, test_version:"12.1.0.1") ||
     version_is_equal(version:ver, test_version:"11.1.0.7"))
  {
    security_message(port);
  }
}
