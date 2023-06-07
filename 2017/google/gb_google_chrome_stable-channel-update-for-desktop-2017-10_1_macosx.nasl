##############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Security Updates(stable-channel-update-for-desktop-2017-10-1)-Mac OS X
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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811884");
  script_version("2021-10-12T09:28:32+0000");
  script_cve_id("CVE-2017-15396", "CVE-2017-15406");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-12 09:28:32 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-31 15:50:00 +0000 (Wed, 31 Oct 2018)");
  script_tag(name:"creation_date", value:"2017-10-27 11:03:14 +0530 (Fri, 27 Oct 2017)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2017-10-1)-Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple stack overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to multiple stack
  overflow errors in V8.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code or cause denial of service.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  62.0.3202.75 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 62.0.3202.75
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/search/label/Stable%20updates");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
chr_ver = infos['version'];
path = infos['location'];

if(version_is_less(version:chr_ver, test_version:"62.0.3202.75"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"62.0.3202.75", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
