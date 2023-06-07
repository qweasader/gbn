###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java SE Multiple Remote Code Execution Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803156");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-3174", "CVE-2013-0422");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2013-01-17 12:41:59 +0530 (Thu, 17 Jan 2013)");
  script_name("Oracle Java SE Multiple Remote Code Execution Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51820/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57246");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57312");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027972");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/625617");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/java/javase/7u11-relnotes-1896856.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/alert-cve-2013-0422-1896849.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code
  via unspecified vectors.");
  script_tag(name:"affected", value:"Oracle Java version 7 before Update 11 on windows");
  script_tag(name:"solution", value:"Upgrade to Oracle Java 7 Update 11 or later.");
  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple code execution vulnerabilities.");
  script_tag(name:"insight", value:"- An error in Java Management Extensions (JMX) MBean components which allows
    remote attackers to execute arbitrary code via unspecified vectors.

  - An unspecified error exists within the Libraries subcomponent.

  NOTE: The vendor reports that only version 7.x is affected. However,
        some security researchers indicate that some 6.x versions may
        be affected");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(jreVer)
{
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.10")){
    report = report_fixed_ver(installed_version:jreVer, vulnerable_range:"1.7 - 1.7.0.10");
    security_message(port: 0, data: report);
  }
}
