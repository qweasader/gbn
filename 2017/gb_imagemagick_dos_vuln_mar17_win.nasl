###############################################################################
# OpenVAS Vulnerability Test
#
# ImageMagick Denial of Service Vulnerability Mar17 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810580");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2016-9559");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-28 19:21:00 +0000 (Wed, 28 Apr 2021)");
  script_tag(name:"creation_date", value:"2017-03-09 12:18:46 +0530 (Thu, 09 Mar 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("ImageMagick Denial of Service Vulnerability Mar17 (Windows)");

  script_tag(name:"summary", value:"ImageMagick is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a NULL pointer
  dereference error in 'coders/tiff.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to cause a denial of service condition.");

  script_tag(name:"affected", value:"ImageMagick versions before 7.0.3.7
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  7.0.3.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/11/23/4");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94489");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/b61d35eaccc0a7ddeff8a1c3abfcd0a43ccf210b");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_imagemagick_detect_win.nasl");
  script_mandatory_keys("ImageMagick/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!imVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:imVer, test_version:"7.0.3.7"))
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:'7.0.3.7');
  security_message(data:report);
  exit(0);
}
