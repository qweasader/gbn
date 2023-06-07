###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java SE Multiple Vulnerabilities - October 2011 (Windows02)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.802274");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2011-3544", "CVE-2011-3546", "CVE-2011-3550", "CVE-2011-3551",
                "CVE-2011-3553", "CVE-2011-3558", "CVE-2011-3561");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2011-11-15 14:34:22 +0530 (Tue, 15 Nov 2011)");
  script_name("Oracle Java SE Multiple Vulnerabilities - October 2011 (Windows02)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46512");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50218");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50224");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50226");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50239");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50242");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50246");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50250");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpuoct2011-443431.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors.");
  script_tag(name:"affected", value:"Oracle Java SE versions 7, 6 Update 27 and earlier.");
  script_tag(name:"insight", value:"Multiple flaws are due to unspecified errors in the following
  components:

  - Scripting

  - Deployment

  - AWT

  - 2D

  - JAXWS

  - HotSpot");
  script_tag(name:"solution", value:"Upgrade to Oracle Java SE versions 7 Update 1, 6 Update 29 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");
  exit(0);
}


include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(jreVer)
{

  if(version_is_equal(version:jreVer, test_version:"1.7.0") ||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.27"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");
if(jdkVer)
{

  if(version_is_equal(version:jdkVer, test_version:"1.7.0") ||
     version_in_range(version:jdkVer, test_version:"1.6", test_version2:"1.6.0.27")) {
     security_message( port: 0, data: "The target host was found to be vulnerable" );
     exit(0);
  }
}

exit(99);
