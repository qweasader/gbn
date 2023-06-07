###############################################################################
# OpenVAS Vulnerability Test
#
# Xvid Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800580");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-06-09 08:37:33 +0200 (Tue, 09 Jun 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0893", "CVE-2009-0894");
  script_name("Xvid Buffer overflow Vulnerability (Windows) - Jun09");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_xvid_detect_win.nasl");
  script_mandatory_keys("Xvid/Win/Ver");
  script_tag(name:"impact", value:"Remote attackers may exploit this issue to cause multiple heap based buffer
  overflow, execute arbitrary code and may cause denial of service.");
  script_tag(name:"affected", value:"Xvid before 1.2.2 on Windows.");
  script_tag(name:"insight", value:"- Inadequate sanitation of user supplied data in 'decoder_iframe',
    'decoder_pframe' and 'decoder_bframe' functions in xvidcore/src/decoder.c
    and can be exploited by providing a crafted macroblock (aka MBlock) number
    in a video stream in a crafted movie file.

  - A boundary error in 'decoder_create' function n xvidcore/src/decoder.c
    can be exploited via vectors involving the DirectShow (aka DShow) frontend
    and improper handling of the XVID_ERR_MEMORY return code during processing
    of a crafted movie file");
  script_tag(name:"solution", value:"Upgrade to Xvid 1.2.2 or later.");
  script_tag(name:"summary", value:"Xvid is prone to a buffer overflow vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35274");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35156");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35158");
  script_xref(name:"URL", value:"http://cvs.xvid.org/cvs/viewvc.cgi/xvidcore/src/decoder.c");
  script_xref(name:"URL", value:"http://cvs.xvid.org/cvs/viewvc.cgi/xvidcore/src/decoder.c?r1=1.80&r2=1.81");
  exit(0);
}

include("version_func.inc");

xvidVer = get_kb_item("Xvid/Win/Ver");
if(!xvidVer)
  exit(0);

if(version_is_less(version:xvidVer, test_version:"1.2.2")){
  report = report_fixed_ver(installed_version:xvidVer, fixed_version:"1.2.2");
  security_message(port: 0, data: report);
}
