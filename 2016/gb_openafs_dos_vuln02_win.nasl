###############################################################################
# OpenVAS Vulnerability Test
#
# OpenAFS Denial of Service Vulnerability-02 (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:openafs:openafs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808079");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2014-4044");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2016-06-09 11:27:44 +0530 (Thu, 09 Jun 2016)");
  script_name("OpenAFS Denial of Service Vulnerability-02 (Windows)");

  script_tag(name:"summary", value:"OpenAFS is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the code does not
  properly zero fields in the host structure in the OpenAFS fileserver.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (uninitialized memory access and crash)
  via unspecified vectors related to TMAY requests.");

  script_tag(name:"affected", value:"OpenAFS version 1.6.8 on Windows.");

  script_tag(name:"solution", value:"Update to OpenAFS version 1.6.9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2014/06/12/1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68003");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_openafs_detect.nasl");
  script_mandatory_keys("OpenAFS/Win/Installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!afsVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:afsVer, test_version:"1.6.8"))
{
  report = report_fixed_ver(installed_version:afsVer, fixed_version: "1.6.9");
  security_message(data:report);
  exit(0);
}
