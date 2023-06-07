###############################################################################
# OpenVAS Vulnerability Test
#
# Java Runtime Environment Multiple Vulnerabilities (MAC OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802738");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2011-3563", "CVE-2011-5035", "CVE-2012-0497", "CVE-2012-0498",
                "CVE-2012-0499", "CVE-2012-0500", "CVE-2012-0501", "CVE-2012-0502",
                "CVE-2012-0503", "CVE-2012-0505", "CVE-2012-0506", "CVE-2012-0507");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2012-04-09 17:06:23 +0530 (Mon, 09 Apr 2012)");
  script_name("Java Runtime Environment Multiple Vulnerabilities (MAC OS X)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5228");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51194");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52009");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52012");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52013");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52014");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52015");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52016");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52017");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52018");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52019");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52161");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT1222");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/111594/Apple-Security-Advisory-2012-04-03-1.html");

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_jre_detect_macosx.nasl");
  script_mandatory_keys("JRE/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a denial of service or
  possibly execute arbitrary code.");
  script_tag(name:"affected", value:"Java Runtime Environment (JRE) version 1.6.0_29");
  script_tag(name:"insight", value:"The flaws are due to multiple unspecified errors in th application.");
  script_tag(name:"solution", value:"Upgrade to Java Runtime Environment (JRE) version 1.6.0_31 or later.");
  script_tag(name:"summary", value:"Java Runtime Environment is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/java/javase/overview/index.html");
  exit(0);
}


include("version_func.inc");

javaVer = get_kb_item("JRE/MacOSX/Version");
if(!javaVer){
  exit(0);
}

javaVer = ereg_replace(pattern:"_", string:javaVer, replace: ".");

if(version_is_equal(version:javaVer, test_version:"1.6.0.29")){
  report = report_fixed_ver(installed_version:javaVer, vulnerable_range:"Equal to 1.6.0.29");
  security_message(port:0, data:report);
}
