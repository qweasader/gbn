###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Shockwave Player Multiple Vulnerabilities - August 2012 (Mac Os X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802939");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-2043", "CVE-2012-2044", "CVE-2012-2045", "CVE-2012-2046",
                "CVE-2012-2047");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-08-20 12:36:45 +0530 (Mon, 20 Aug 2012)");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities - August 2012 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50283/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55025");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55028");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55029");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55030");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55031");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-17.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Shockwave/Player/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of service or
  execute arbitrary code by tricking a user into visiting a specially crafted
  web page.");
  script_tag(name:"affected", value:"Adobe Shockwave Player Versions 11.6.5.635 and prior on Mac OS X");
  script_tag(name:"insight", value:"The flaws are due to multiple unspecified errors in the application.");
  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player version 11.6.6.636 or later.");
  script_tag(name:"summary", value:"Adobe Shockwave Player is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

shockVer = get_kb_item("Adobe/Shockwave/Player/MacOSX/Version");
if(!shockVer){
  exit(0);
}

if(version_is_less_equal(version:shockVer, test_version:"11.6.5.635")){
  report = report_fixed_ver(installed_version:shockVer, vulnerable_range:"Less than or equal to 11.6.5.635");
  security_message(port:0, data:report);
}
