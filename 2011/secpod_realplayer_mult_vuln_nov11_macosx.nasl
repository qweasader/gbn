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
  script_oid("1.3.6.1.4.1.25623.1.0.902761");
  script_version("2022-04-28T13:38:57+0000");
  script_cve_id("CVE-2011-4253", "CVE-2011-4252", "CVE-2011-4250", "CVE-2011-4246",
                "CVE-2011-4245", "CVE-2011-4255", "CVE-2011-4256");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-11-29 13:01:59 +0530 (Tue, 29 Nov 2011)");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities Nov - 11 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46963/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50741");
  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/11182011_player/en/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_realplayer_detect_macosx.nasl");
  script_mandatory_keys("RealPlayer/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code or
  cause a denial of service.");
  script_tag(name:"affected", value:"RealPlayer version prior to 12.0.0.1703 on Mac OS X");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Unspecified errors in RV20, RV10, RV30, ATRC and AAC codec, allows
    attackers to execute arbitrary code via unspecified vectors.

  - An unspecified error related to RealVideo rendering can be exploited
    to corrupt memory.");
  script_tag(name:"solution", value:"Upgrade to RealPlayer version 12.0.0.1703 or later.");
  script_tag(name:"summary", value:"RealPlayer is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

rpVer = get_kb_item("RealPlayer/MacOSX/Version");
if(isnull(rpVer)){
  exit(0);
}

if(version_is_less(version:rpVer, test_version:"12.0.0.1703")){
  report = report_fixed_ver(installed_version:rpVer, fixed_version:"12.0.0.1703");
  security_message(port: 0, data: report);
}
