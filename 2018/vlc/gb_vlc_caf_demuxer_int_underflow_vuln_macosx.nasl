###############################################################################
# OpenVAS Vulnerability Test
#
# VLC Media Player CAF Demuxer Integer Underflow Vulnerability (Mac OS X)
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814376");
  script_version("2021-10-11T09:46:29+0000");
  script_cve_id("CVE-2018-19857");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-10-11 09:46:29 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-25 17:15:00 +0000 (Thu, 25 Jul 2019)");
  script_tag(name:"creation_date", value:"2018-12-17 10:49:31 +0530 (Mon, 17 Dec 2018)");
  ## not able to detect patched versions
  script_tag(name:"qod_type", value:"executable_version");
  script_name("VLC Media Player CAF Demuxer Integer Underflow Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"VLC media player is prone to an integer underflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper handling
  of magic cookies in Core Audio Format (CAF) files, which could result in an
  uninitialized memory read in the CAF demuxer.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code in the context of the affected application and failed
  exploit attempts will likely result in denial of service conditions.");

  script_tag(name:"affected", value:"VideoLAN VLC media player version 3.0.4 on Mac OS X");

  script_tag(name:"solution", value:"Apply patch from Reference. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://dyntopia.com/advisories/013-vlc");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vlcVer = infos['version'];
vlcpath = infos['location'];

if(version_is_equal(version:vlcVer, test_version:"3.0.4"))
{
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"3.0.4", install_path: vlcpath);
  security_message(data:report);
  exit(0);
}
exit(99);
