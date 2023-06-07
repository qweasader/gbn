###############################################################################
# OpenVAS Vulnerability Test
#
# Google SketchUp '.SKP' File Memory Corruption Vulnerability (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803039");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-4894");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-10-09 17:33:06 +0530 (Tue, 09 Oct 2012)");
  script_name("Google SketchUp '.SKP' File Memory Corruption Vulnerability (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50663");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55598");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/VulnerabilityResearchAdvisories/2012/msvr12-015");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_google_sketchup_detect_macosx.nasl");
  script_mandatory_keys("Google/SketchUp/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow the attacker to execute arbitrary code in
  the context of the user running the application which can compromise the
  application and possibly the system.");
  script_tag(name:"affected", value:"Google SketchUp version 8 Maintenance Release 2 and prior on Mac OS X");
  script_tag(name:"insight", value:"SketchUp fails to parse specially crafted SketchUp document (SKP) files and
  can be exploited to execute arbitrary code or cause a denial of service
  (memory corruption) via a crafted SKP file.");
  script_tag(name:"solution", value:"Upgrade to Google SketchUp version 8 Maintenance Release 3 or later.");
  script_tag(name:"summary", value:"Google SketchUp is prone to a memory corruption vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

gsVer = get_kb_item("Google/SketchUp/MacOSX/Version");
if(!gsVer){
  exit(0);
}

if(version_is_less_equal(version:gsVer, test_version:"8.0.11751.0")){
  report = report_fixed_ver(installed_version:gsVer, vulnerable_range:"Less than or equal to 8.0.11751.0");
  security_message(port:0, data:report);
}
