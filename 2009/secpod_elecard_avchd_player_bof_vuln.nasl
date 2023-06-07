# Copyright (C) 2009 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900627");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1356");
  script_name("Elecard AVC HD Player Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8452");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34560");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/378145.php");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_elecard_avchd_player_detect.nasl");
  script_mandatory_keys("Elecard/AVC/HD/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code
  in the context of the affected application.");

  script_tag(name:"affected", value:"Elecard AVC HD Player 5.5.90213 and prior on Windows.");

  script_tag(name:"insight", value:"Application fails to perform adequate boundary checks on user-supplied input
  which results in a buffer overflow while processing playlist(.xpl) containing long MP3 filenames.");

  script_tag(name:"solution", value:"Upgrade to Elecard AVC HD Player version 5.6.90515 or later.");

  script_tag(name:"summary", value:"Elecard AVC HD Player is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

avcPlayer = get_kb_item("Elecard/AVC/HD/Ver");
if(!avcPlayer)
  exit(0);

if(version_is_less_equal(version:avcPlayer, test_version:"5.5.90213")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
