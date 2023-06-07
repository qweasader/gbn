###############################################################################
# OpenVAS Vulnerability Test
#
# VLC Media Player M3U Denial of Service Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804125");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-6283");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-11-05 12:38:13 +0530 (Tue, 05 Nov 2013)");
  script_name("VLC Media Player M3U Denial of Service Vulnerability (Windows)");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of service
and possibly execute arbitrary remote code.");
  script_tag(name:"affected", value:"VLC media player version 2.0.8 and prior on Windows");
  script_tag(name:"insight", value:"The flaw exists due to improper handling of a specially crafted M3U file.");
  script_tag(name:"solution", value:"Upgrade to VLC media player version 2.1.0 or later.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"summary", value:"VLC Media Player is prone to denial of service and remote code execution vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/447008.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61844");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27700");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

vlcVer = get_app_version(cpe:CPE);
if(!vlcVer){
  exit(0);
}

if(version_is_less_equal(version:vlcVer, test_version:"2.0.8"))
{
  report = report_fixed_ver(installed_version:vlcVer, vulnerable_range:"Less than or equal to 2.0.8");
  security_message(port: 0, data: report);
  exit(0);
}
