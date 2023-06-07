###############################################################################
# OpenVAS Vulnerability Test
#
# VLC Media Player 3GP File Denial of Service Vulnerability Oct15 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806088");
  script_version("2022-04-14T06:42:08+0000");
  script_cve_id("CVE-2015-5949");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 06:42:08 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2015-10-13 16:16:33 +0530 (Tue, 13 Oct 2015)");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_name("VLC Media Player 3GP File Denial of Service Vulnerability Oct15 (Mac OS X)");

  script_tag(name:"summary", value:"VLC media player is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to insufficient
  restrictions on a writable buffer which affects the 3GP file format parser.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (crash) and possibly execute arbitrary
  code via a crafted 3GP file.");

  script_tag(name:"affected", value:"VideoLAN VLC media player 2.2.1 and
  earlier on Mac OS X.");

  script_tag(name:"solution", value:"Updates are available, please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133266");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76448");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/536287/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vlcVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:vlcVer, test_version:"2.2.1"))
{
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"2.2.2");
  security_message(data:report);
  exit(0);
}
