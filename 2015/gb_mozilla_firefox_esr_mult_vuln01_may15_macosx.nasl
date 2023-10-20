# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805628");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-0797", "CVE-2015-2708", "CVE-2015-2710", "CVE-2015-2713",
                "CVE-2015-2716");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-05-21 18:31:24 +0530 (Thu, 21 May 2015)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities-01 May15 (Mac OS X)");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Buffer overflow in the XML parser in Mozilla Firefox.

  - Use-after-free vulnerability in the SetBreaks function in Mozilla Firefox.

  - Heap-based buffer overflow in the SVGTextFrame class in Mozilla Firefox.

  - Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox.

  - Flaw in GStreamer in Mozilla Firefox.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  context-dependent attacker to execute arbitrary code, gain unauthorized access
  to information or to cause the server to crash.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR 31.x before 31.7 on
  Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version
  31.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-54");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74611");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74615");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2015/mfsa2015-47.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers =~ "^31\.")
{
  if((version_in_range(version:vers, test_version:"31.0", test_version2:"31.6")))
  {
    report = 'Installed version: ' + vers + '\n' +
             'Fixed version:     ' + "31.7"  + '\n';
    security_message(data:report);
    exit(0);
  }
}
