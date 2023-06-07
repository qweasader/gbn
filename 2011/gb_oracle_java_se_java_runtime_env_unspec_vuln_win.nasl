###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java SE Java Runtime Environment Unspecified Vulnerability - October 2011 (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802277");
  script_version("2022-04-28T13:38:57+0000");
  script_cve_id("CVE-2011-3555");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:C");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-11-15 14:34:22 +0530 (Tue, 15 Nov 2011)");
  script_name("Oracle Java SE Java Runtime Environment Unspecified Vulnerability - October 2011 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46512");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50237");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/70838");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpuoct2011-443431.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to cause a denial of service.");
  script_tag(name:"affected", value:"Oracle Java SE versions 7.");
  script_tag(name:"insight", value:"The flaw is due to unspecified error in the Java Runtime Environment
  component.");
  script_tag(name:"solution", value:"Upgrade to Oracle Java SE versions 7 Update 1 or later.");
  script_tag(name:"summary", value:"Oracle Java SE is prone to an unspecified vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(jreVer)
{

  if(version_is_equal(version:jreVer, test_version:"1.7.0"))
  {
    report = report_fixed_ver(installed_version:jreVer, vulnerable_range:"Equal to 1.7.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");
if(jdkVer)
{

  if(version_is_equal(version:jdkVer, test_version:"1.7.0")) {
    report = report_fixed_ver(installed_version:jdkVer, vulnerable_range:"Equal to 1.7.0");
    security_message(port: 0, data: report);
  }
}
