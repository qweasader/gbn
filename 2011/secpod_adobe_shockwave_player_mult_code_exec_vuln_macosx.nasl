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
  script_oid("1.3.6.1.4.1.25623.1.0.902620");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_cve_id("CVE-2010-4308", "CVE-2010-4309", "CVE-2011-2419", "CVE-2011-2420",
                "CVE-2011-2421", "CVE-2011-2422", "CVE-2011-2423");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Adobe Shockwave Player Multiple Remote Code Execution Vulnerabilities (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45584");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49102");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-19.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Shockwave/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of service or
  execute arbitrary code by tricking a user into visiting a specially crafted
  web page.");
  script_tag(name:"affected", value:"Adobe Shockwave Player Versions prior to 11.6.1.629 on Mac OS X.");
  script_tag(name:"insight", value:"Multiple flaws are caused by memory corruptions errors in the IML32.dll,
  Dirapi.dll, Textra.x32 and msvcr90.dll component when processing malformed
  '.dir' media file.");
  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player version 11.6.1.629 or later.");
  script_tag(name:"summary", value:"Adobe Shockwave Player is prone to multiple remote code execution vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

shockVer = get_kb_item("Adobe/Shockwave/MacOSX/Version");
if(!shockVer){
  exit(0);
}

if(version_is_less(version:shockVer, test_version:"11.6.1.629")){
  report = report_fixed_ver(installed_version:shockVer, fixed_version:"11.6.1.629");
  security_message(port: 0, data: report);
}
