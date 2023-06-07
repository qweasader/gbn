###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Tivoli Storage Manager Information Disclosure Vulnerability - Windows
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

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ibm:tivoli_storage_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811128");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2016-8916");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-17 18:12:00 +0000 (Wed, 17 May 2017)");
  script_tag(name:"creation_date", value:"2017-06-02 15:14:26 +0530 (Fri, 02 Jun 2017)");
  script_name("IBM Tivoli Storage Manager Information Disclosure Vulnerability - Windows");

  script_tag(name:"summary", value:"IBM Tivoli Storage Manager is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error while using the
  'set password' command, the full text of the command and included password is
  written to the instrumentation log file if instrumentation tracing is enabled.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  user to get the password information.");

  script_tag(name:"affected", value:"IBM Tivoli Storage Manager version 7.1.0.0
  through 7.1.6.4, 6.4.0.0 through 6.4.3.4, 6.3, 6.2, 6.1, and 5.5 all levels

  - ----
  NOTE: 6.3, 6.2, 6.1, and 5.5 all levels releases are EOS.

  - ----");

  script_tag(name:"solution", value:"Upgrade to IBM Tivoli Storage Manager version
  6.4.3.5, 7.1.6.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21998166");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98335");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ibm_tsm_client_detect.nasl");
  script_mandatory_keys("IBM/Tivoli/Storage/Manager/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!tivVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:tivVer, test_version:"5.5", test_version2:"6.4.3.4")){
  fix = "6.4.3.5";
}

else if(version_in_range(version:tivVer, test_version:"7.1", test_version2:"7.1.6.4")){
  fix = "7.1.6.5";
}

if(fix)
{
  report = report_fixed_ver(installed_version:tivVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}