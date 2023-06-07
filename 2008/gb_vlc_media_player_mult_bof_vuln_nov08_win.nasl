###############################################################################
# OpenVAS Vulnerability Test
#
# VLC Media Player Multiple Stack-Based BOF Vulnerabilities - Nov08 (Windows)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800132");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-11-14 10:43:16 +0100 (Fri, 14 Nov 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5032", "CVE-2008-5036");
  script_name("VLC Media Player Multiple Stack-Based BOF Vulnerabilities - Nov08 (Windows)");

  script_xref(name:"URL", value:"http://www.videolan.org/security/sa0810.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32125");
  script_xref(name:"URL", value:"http://www.trapkit.de/advisories/TKADV2008-011.txt");
  script_xref(name:"URL", value:"http://www.trapkit.de/advisories/TKADV2008-012.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code
  within the context of the VLC media player by tricking a user into opening
  a specially crafted file or can even crash an affected application.");

  script_tag(name:"affected", value:"VLC media player 0.5.0 through 0.9.5 on Windows (Any).");

  script_tag(name:"insight", value:"The flaws are caused while parsing,

  - header of an invalid CUE image file related to modules/access/vcd/cdrom.c.

  - an invalid RealText(rt) subtitle file related to the ParseRealText function
    in modules/demux/subtitle.c.");

  script_tag(name:"summary", value:"VLC Media Player is prone to Multiple Stack-Based Buffer Overflow Vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to 0.9.6 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://git.videolan.org/?p=vlc.git;a=commitdiff;h=e3cef651125701a2e33a8d75b815b3e39681a447");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

vlcVer = registry_get_sz(item:"Version", key:"SOFTWARE\VideoLAN\VLC");
if(!vlcVer){
  exit(0);
}

if(version_in_range(version:vlcVer, test_version:"0.5.0", test_version2:"0.9.5")){
  report = report_fixed_ver(installed_version:vlcVer, vulnerable_range:"0.5.0 - 0.9.5");
  security_message(port: 0, data: report);
}
