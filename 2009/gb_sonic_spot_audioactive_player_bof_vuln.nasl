###############################################################################
# OpenVAS Vulnerability Test
#
# Sonic Spot Audioactive Player Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800572");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-06-09 08:37:33 +0200 (Tue, 09 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1815");
  script_name("Sonic Spot Audioactive Player Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8701");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34987");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8698");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1339");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_sonic_spot_audioactive_player_detect.nasl");
  script_mandatory_keys("SonicSpot/Audoiactive/Player/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary
codes in the context of the application and may cause stack overflow in the
application.");
  script_tag(name:"affected", value:"Audioactive Player version 1.93b and prior on Windows.");
  script_tag(name:"insight", value:"A boundary error occurs while processing playlist ('.mp3', '.m3u')
files containing overly long data leading to a buffer overflow.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Sonic Spot Audioactive Player is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

audiactivepVer = get_kb_item("SonicSpot/Audoiactive/Player/Ver");

if(!audiactivepVer){
  exit(0);
}

if(version_is_less_equal(version:audiactivepVer, test_version:"1.93b")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
