# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802948");
  script_version("2024-07-17T05:05:38+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-1718", "CVE-2012-1711", "CVE-2012-1713", "CVE-2012-1719",
                "CVE-2012-1720", "CVE-2012-1723");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:38:00 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-08-22 18:44:44 +0530 (Wed, 22 Aug 2012)");
  script_name("Oracle Java SE Java Runtime Environment Multiple Unspecified Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48589");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53946");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53949");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53950");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53951");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53956");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53960");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027153");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpujun2012-1515912.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code on
  the target system or cause complete denial of service conditions.");
  script_tag(name:"affected", value:"Oracle Java SE 7 update 4 and earlier, 6 update 32 and earlier,
  5 update 35 and earlier, and 1.4.2_37 and earlier");
  script_tag(name:"insight", value:"Many unspecified vulnerabilities in the application.");
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
  if(version_is_less_equal(version:jreVer, test_version:"1.4.2.37") ||
     version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.4") ||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.32") ||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.35")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
