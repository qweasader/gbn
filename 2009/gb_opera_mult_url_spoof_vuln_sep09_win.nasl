# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800887");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3044", "CVE-2009-3045", "CVE-2009-3046",
                "CVE-2009-3047", "CVE-2009-3049");
  script_name("Opera Multiple URL Spoofing Vulnerabilities - Sep09 (Windows)");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/934/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/933/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/929/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/930/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/932/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/windows/1000/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct URL spoofing, and
  bypass certain security restrictions.");
  script_tag(name:"affected", value:"Opera version prior to 10.00 on Windows.");
  script_tag(name:"insight", value:"- Opera fails to handle a '\0' character or invalid wildcard character in a
    domain name in the subject's Common Name (CN) field of an X.509 certificate.

  - The Trusts root X.509 certificates signed with the MD2 algorithm, which
    makes it easier for man-in-the-middle attackers to spoof arbitrary SSL
    servers via a crafted server certificate.

  - Opera fails to check all intermediate X.509 certificates for revocation.

  - When a collapsed address bar is used, Opera does not properly update the
    domain name from the previously visited site to the currently visited site.

  - Opera fails to display all characters in Internationalized Domain Names
    (IDN) in the address bar.");
  script_tag(name:"solution", value:"Upgrade to Opera version 10.00.");
  script_tag(name:"summary", value:"Opera Web Browser is prone to Multiple Spoof URL vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer)
  exit(0);

if(version_is_less(version:operaVer, test_version:"10.00")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"10.00");
  security_message(port: 0, data: report);
}
