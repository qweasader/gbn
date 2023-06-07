###############################################################################
# OpenVAS Vulnerability Test
#
# VLC Media Player Denial of Service Vulnerability -01 June14 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804615");
  script_version("2021-10-28T14:26:49+0000");
  script_cve_id("CVE-2014-3441");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-10-28 14:26:49 +0000 (Thu, 28 Oct 2021)");
  script_tag(name:"creation_date", value:"2014-06-04 11:20:43 +0530 (Wed, 04 Jun 2014)");
  script_name("VLC Media Player Denial of Service Vulnerability -01 June14 (Linux)");

  script_tag(name:"summary", value:"VLC Media Player is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw exists as user-supplied input is not properly sanitized when handling
a specially crafted WAV file.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial of service
conditions or potentially execute arbitrary code.");
  script_tag(name:"affected", value:"VLC media player version 2.1.3 on Linux.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126564");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_vlc_media_player_detect_lin.nasl");
  script_mandatory_keys("VLCPlayer/Lin/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

vlcVer = get_app_version(cpe:CPE);
if(!vlcVer){
  exit(0);
}

if(version_is_equal(version:vlcVer, test_version:"2.1.3"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}