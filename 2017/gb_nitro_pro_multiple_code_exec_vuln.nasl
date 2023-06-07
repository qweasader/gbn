###############################################################################
# OpenVAS Vulnerability Test
#
# Nitro Pro Multiple Code Execution Vulnerabilities (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:nitro_software:nitro_pro";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811272");
  script_version("2022-12-15T10:11:09+0000");
  script_cve_id("CVE-2016-8713", "CVE-2016-8709", "CVE-2016-8711");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-12-15 10:11:09 +0000 (Thu, 15 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-13 21:58:00 +0000 (Tue, 13 Dec 2022)");
  script_tag(name:"creation_date", value:"2017-08-04 15:46:10 +0530 (Fri, 04 Aug 2017)");
  script_name("Nitro Pro Multiple Code Execution Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"Nitro Pro is prone to multiple code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple remote out of bound write errors in the PDF parsing functionality
    of Nitro Pro.

  - Multiple memory corruption errors in the PDF parsing functionality
    of Nitro Pro.

  - An enspecified design error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of current user.");

  script_tag(name:"affected", value:"Nitro Pro version 10.5.9.9");

  script_tag(name:"solution", value:"Upgrade to Nitro Pro version 11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.gonitro.com/product/downloads#securityUpdates");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96155");
  script_xref(name:"URL", value:"https://www.talosintelligence.com/reports/TALOS-2016-0218");
  script_xref(name:"URL", value:"https://www.talosintelligence.com/reports/TALOS-2016-0224");
  script_xref(name:"URL", value:"https://www.talosintelligence.com/reports/TALOS-2016-0226");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_nitro_pro_detect_win.nasl");
  script_mandatory_keys("Nitro/Pro/Win/Ver");
  script_xref(name:"URL", value:"https://www.gonitro.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!nitroVer = get_app_version(cpe:CPE, nofork:TRUE)){
  exit(0);
}

if(version_is_equal(version:nitroVer, test_version:"10.5.9.9"))
{
  report = report_fixed_ver(installed_version:nitroVer, fixed_version:"Nitro Pro 11");
  security_message(data:report);
  exit(0);
}
