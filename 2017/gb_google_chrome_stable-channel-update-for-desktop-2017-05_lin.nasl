##############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Security Updates(stable-channel-update-for-desktop-2017-05)-Linux
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810771");
  script_version("2022-04-11T03:04:18+0000");
  script_cve_id("CVE-2017-5068");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-11 03:04:18 +0000 (Mon, 11 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-08 10:50:00 +0000 (Fri, 08 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-05-03 11:37:14 +0530 (Wed, 03 May 2017)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2017-05)-Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to race condition vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw exists due to the Race condition in WebRTC.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code or to cause a denial of service.");

  script_tag(name:"affected", value:"Google Chrome version prior to 58.0.3029.96 on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  58.0.3029.96 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/05/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chr_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chr_ver, test_version:"58.0.3029.96"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"58.0.3029.96");
  security_message(data:report);
  exit(0);
}