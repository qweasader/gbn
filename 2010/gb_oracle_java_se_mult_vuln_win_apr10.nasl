# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800499");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-07 16:20:50 +0200 (Wed, 07 Apr 2010)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2009-3555", "CVE-2010-0082", "CVE-2010-0084", "CVE-2010-0085",
                "CVE-2010-0087", "CVE-2010-0088", "CVE-2010-0089", "CVE-2010-0090",
                "CVE-2010-0091", "CVE-2010-0092", "CVE-2010-0093", "CVE-2010-0094",
                "CVE-2010-0095", "CVE-2010-0837", "CVE-2010-0838", "CVE-2010-0839",
                "CVE-2010-0840", "CVE-2010-0841", "CVE-2010-0842", "CVE-2010-0843",
                "CVE-2010-0844", "CVE-2010-0845", "CVE-2010-0846", "CVE-2010-0847",
                "CVE-2010-0848", "CVE-2010-0849");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Oracle Java SE Multiple Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0747");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36935");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39062");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39065");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39067");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39068");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39069");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39070");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39071");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39072");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39073");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39075");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39077");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39078");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39081");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39083");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39084");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39085");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39086");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39088");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39089");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39090");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39091");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39093");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39094");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39095");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39096");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Mar/1023774.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technology/deploy/security/critical-patch-updates/javacpumar2010.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");

  script_tag(name:"impact", value:"Successful attacks will allow attackers to affect confidentiality, integrity,
  and availability via unknown vectors.");

  script_tag(name:"affected", value:"Sun Java SE version 6 Update 18, 5.0 Update 23 on Windows.");

  script_tag(name:"insight", value:"Multiple flaws are due to memory corruptions, buffer overflows, input
  validation and implementation errors in following components,

  - HotSpot Server

  - Java Runtime Environment

  - Java Web Start

  - Java Plug-in

  - Java 2D

  - Sound and

  - imageIO components.");

  script_tag(name:"solution", value:"Upgrade to SE 6 Update 19, JDK and JRE 5.0 Update 24.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Sun Java SE is prone to multiple vulnerabilities.");

  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");
if(jdkVer)
{
  if(version_in_range(version:jdkVer, test_version:"1.6", test_version2:"1.6.0.18") ||
     version_in_range(version:jdkVer, test_version:"1.5", test_version2:"1.5.0.23")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(jreVer)
{
  if(version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.18") ||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.23")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);
