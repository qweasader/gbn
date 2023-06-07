###############################################################################
# OpenVAS Vulnerability Test
#
# Sun Java JDK/JRE JPEG Images Integer Overflow Vulnerability - Aug09
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800868");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2674", "CVE-2009-2476", "CVE-2009-2690",
                "CVE-2009-2716", "CVE-2009-2719", "CVE-2009-2720");
  script_name("Sun Java JDK/JRE JPEG Images Integer Overflow Vulnerability - Aug09");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36159");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35942");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36162");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36176");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36180");
  script_xref(name:"URL", value:"http://java.sun.com/javase/6/webnotes/6u15.html");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-050/");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-263428-1");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-21-125136-16-1");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-21-125139-16-1");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl", "gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win_or_Linux/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain sensitive
  information, and can cause Denial of Service in the context of the affected system.");

  script_tag(name:"affected", value:"Sun Java JDK/JRE version 6 before Update 15.");

  script_tag(name:"insight", value:"Multiple flaws exist:

  - Integer overflow occurs in JRE while vectors involving an untrusted Java Web
    Start application that grants permissions to itself, related to parsing of
    JPEG images.

  - Error in the Java Management Extensions (JMX) implementation which does not
    properly enforce OpenType checks.

  - Error in encoder which grants read access to private variables with unspecified
    names via an untrusted applet or application.

  - The plugin functionality does not properly implement version selection,
    which can be exploited by 'old zip and certificate handling' via unknown
    vectors.

  - Unspecified error in the 'javax.swing.plaf.synth.SynthContext.isSubregion'
    method in the Swing implementation which causes NullPointerException via
    unknown vectors.

  - Error in Java Web Start implementation which causes NullPointerException
    via a crafted '.jnlp' file.");

  script_tag(name:"summary", value:"Sun Java JDK/JRE is prone to an integer overflow vulnerability.");

  script_tag(name:"solution", value:"Upgrade to JDK/JRE version 6 Update 15.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");

if(jdkVer)
{
  if(version_in_range(version:jdkVer, test_version:"1.6", test_version2:"1.6.0.14"))
  {
    report = report_fixed_ver(installed_version:jdkVer, vulnerable_range:"1.6 - 1.6.0.14");
    security_message(port: 0, data: report);
    exit(0);
  }
}

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(isnull(jreVer))
{
  jreVer = get_kb_item("Sun/Java/JRE/Linux/Ver");
  if(isnull(jreVer))
    exit(0);
}

if(jreVer)
{
  if(version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.14")){
    report = report_fixed_ver(installed_version:jreVer, vulnerable_range:"1.6 - 1.6.0.14");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
