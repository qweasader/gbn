# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902623");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-08-31 10:37:30 +0200 (Wed, 31 Aug 2011)");
  script_cve_id("CVE-2011-2948", "CVE-2011-2951");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44014/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49173");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49175");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45668/");
  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/08162011_player/en/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_realplayer_detect_macosx.nasl");
  script_mandatory_keys("RealPlayer/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary
  code or cause a denial of service.");
  script_tag(name:"affected", value:"RealPlayer version 12.0.0.1569 and prior on Mac OS X");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Improper handling of DEFINEFONT fields in SWF files which allows remote
    attackers to execute arbitrary code via a crafted file.

  - A buffer overflow error which allows remote attackers to execute arbitrary
    code via a crafted raw_data_frame field in an AAC file.");
  script_tag(name:"solution", value:"Upgrade to RealPlayer version 12.0.0.1701 or later.");
  script_tag(name:"summary", value:"RealPlayer is prone to multiple vulnerabilities");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

rpVer = get_kb_item("RealPlayer/MacOSX/Version");
if(isnull(rpVer)){
  exit(0);
}

if(version_is_less(version:rpVer, test_version:"12.0.0.1569")){
  report = report_fixed_ver(installed_version:rpVer, fixed_version:"12.0.0.1569");
  security_message(port: 0, data: report);
}
