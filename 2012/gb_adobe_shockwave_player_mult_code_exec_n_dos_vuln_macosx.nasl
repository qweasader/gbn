###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Shockwave Player Multiple Code Execution and DoS Vulnerabilities (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802780");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-2029", "CVE-2012-2030", "CVE-2012-2031", "CVE-2012-2032",
                "CVE-2012-2033");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-05-15 12:12:47 +0530 (Tue, 15 May 2012)");
  script_name("Adobe Shockwave Player Multiple Code Execution and DoS Vulnerabilities (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49086/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53420");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-13.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Shockwave/Player/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code or
  to cause a denial of service.");
  script_tag(name:"affected", value:"Adobe Shockwave Player Versions prior to 11.6.5.635 on Mac OS X");
  script_tag(name:"insight", value:"Multiple flaws are due to

  - An error within the IMLLib, DPLib and IMLLib modules when parsing a '.dir'.

  - An unspecified errors.");
  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player version 11.6.5.635 or later.");
  script_tag(name:"summary", value:"Adobe Shockwave Player is prone to multiple code execution and denial of service vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

shockVer = get_kb_item("Adobe/Shockwave/Player/MacOSX/Version");
if(!shockVer){
  exit(0);
}

if(version_is_less(version:shockVer, test_version:"11.6.3.635")){
  report = report_fixed_ver(installed_version:shockVer, fixed_version:"11.6.3.635");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
