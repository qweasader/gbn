# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803041");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2012-4194", "CVE-2012-4195", "CVE-2012-4196");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-11-02 16:08:12 +0530 (Fri, 02 Nov 2012)");
  script_name("Mozilla Firefox Multiple Vulnerabilities - November12 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51144");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56301");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56302");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56306");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027703");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-90.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to inject scripts and bypass
  certain security restrictions.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 16.0.2 on Mac OS X.");

  script_tag(name:"insight", value:"Multiple flaws exist:

  - When handling the 'window.location' object

  - Within CheckURL() function of the 'window.location' object, which can be
    forced to return the wrong calling document and principal

  - Within handling of 'Location' object can be exploited to bypass security
    wrapper protection");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 16.0.2 or later.");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");

if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"16.0.2"))
  {
    report = report_fixed_ver(installed_version:ffVer, fixed_version:"16.0.2");
    security_message(port:0, data:report);
    exit(0);
  }
}
