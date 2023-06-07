###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java SE JRE Multiple Unspecified Vulnerabilities-04 oct12 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802482");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-5086", "CVE-2012-5072");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-10-19 13:02:01 +0530 (Fri, 19 Oct 2012)");
  script_name("Oracle Java SE JRE Multiple Unspecified Vulnerabilities-04 oct12 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50949/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56039");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56083");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/50949");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpuoct2012-1515924.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code on
  the target system or cause complete denial of service conditions.");
  script_tag(name:"affected", value:"Oracle Java SE 7 Update 7 and earlier, and 6 Update 35 and earlier");
  script_tag(name:"insight", value:"Multiple unspecified vulnerabilities exist in the application related
  to Beans and Security.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple unspecified vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(jreVer)
{
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.7") ||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.35")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
