###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java SE Multiple Vulnerabilities -03 May 13 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.803488");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-2438", "CVE-2013-2436", "CVE-2013-2431",
                "CVE-2013-2426", "CVE-2013-2425", "CVE-2013-2423",
                "CVE-2013-2421", "CVE-2013-2416", "CVE-2013-2415",
                "CVE-2013-2434", "CVE-2013-2428", "CVE-2013-2427",
                "CVE-2013-2414", "CVE-2013-1564", "CVE-2013-1561");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2013-05-06 17:27:22 +0530 (Mon, 06 May 2013)");
  script_name("Oracle Java SE Multiple Vulnerabilities -03 May 13 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53008");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59088");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59128");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59137");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59153");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59162");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59165");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59175");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59185");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59191");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59195");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59203");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59206");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59212");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59213");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59234");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpuapr2013-1928497.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpuapr2013verbose-1928687.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors. Attackers can even execute
  arbitrary code on the target system.");
  script_tag(name:"affected", value:"Oracle Java SE Version 7 Update 17 and earlier");
  script_tag(name:"insight", value:"Multiple flaws due to unspecified errors in the JavaFX, Libraries,
  HotSpot, Install, Deployment and JAX-WX components.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(jreVer && jreVer =~ "^(1\.7)")
{
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.17"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
