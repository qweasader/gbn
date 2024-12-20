# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803859");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2013-1701", "CVE-2013-1706", "CVE-2013-1707", "CVE-2013-1709",
                "CVE-2013-1710", "CVE-2013-1712", "CVE-2013-1713", "CVE-2013-1714",
                "CVE-2013-1717");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-08-08 17:09:57 +0530 (Thu, 08 Aug 2013)");
  script_name("Mozilla Thunderbird ESR Multiple Vulnerabilities (Aug 2013) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Thunderbird ESR is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 17.0.8 or later.");
  script_tag(name:"insight", value:"Multiple flaws due to:

  - Error in crypto.generateCRMFRequest function.

  - Does not properly restrict local-filesystem access by Java applets.

  - Multiple Unspecified vulnerabilities in the browser engine.

  - Multiple untrusted search path vulnerabilities updater.exe.

  - Web Workers implementation is not properly restrict XMLHttpRequest calls.

  - Usage of incorrect URI within unspecified comparisons during enforcement
  of the Same Origin Policy.

  - Improper handling of interaction between FRAME elements and history.

  - Stack-based buffer overflow in Mozilla Updater and maintenanceservice.exe.");
  script_tag(name:"affected", value:"Mozilla Thunderbird ESR 17.x before 17.0.8 on Mac OS X");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code, obtain potentially sensitive information, gain escalated privileges, bypass
security restrictions, perform unauthorized actions and other attacks may also be possible.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54413");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61641");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=406541");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-75.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird-ESR/MacOSX/Version");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Thunderbird-ESR/MacOSX/Version");
if(vers && vers =~ "^17\.0")
{
  if(version_in_range(version:vers, test_version:"17.0", test_version2:"17.0.7"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
