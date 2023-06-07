#############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Acrobat Multiple Unspecified Vulnerabilities -01 Feb13 (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.803419");
  script_version("2022-08-09T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2013-02-19 19:32:21 +0530 (Tue, 19 Feb 2013)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-0640", "CVE-2013-0641");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Acrobat Multiple Unspecified Vulnerabilities -01 Feb13 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52196");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57931");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57947");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa13-02.html");
  script_xref(name:"URL", value:"http://blogs.adobe.com/psirt/2013/02/adobe-reader-and-acrobat-vulnerability-report.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Acrobat/MacOSX/Version");

  script_tag(name:"affected", value:"Adobe Acrobat Version 9.x prior to 9.5.4 on Mac OS X

  Adobe Acrobat X Version 10.x prior to 10.1.6 on Mac OS X

  Adobe Acrobat XI Version 11.x prior to 11.0.02 on Mac OS X");

  script_tag(name:"insight", value:"The flaws are due to unspecified errors.");

  script_tag(name:"solution", value:"Upgrade to version 9.5.4 or X (10.1.6) or XI (11.0.02) or later.");

  script_tag(name:"summary", value:"Adobe Acrobat is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  code or cause a denial of service via a crafted PDF document.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

acrobatVer = get_kb_item("Adobe/Acrobat/MacOSX/Version");

if(acrobatVer && acrobatVer =~ "^9|10|11")
{
  if((version_in_range(version:acrobatVer, test_version:"9.0", test_version2: "9.5.3"))||
     (version_in_range(version:acrobatVer, test_version:"10.0", test_version2: "10.1.5"))||
     (version_in_range(version:acrobatVer, test_version:"11.0", test_version2: "11.0.01")))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
