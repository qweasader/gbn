# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900848");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3070", "CVE-2009-3074", "CVE-2009-3076");
  script_name("Mozilla Firefox Multiple Denial Of Service Vulnerabilities (Sep 2009) - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36671/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36343");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-47.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-48.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("Firefox/Linux/Ver");
  script_tag(name:"impact", value:"A remote, unauthenticated attacker could execute arbitrary code or cause
  a vulnerable application to crash.");
  script_tag(name:"affected", value:"Mozilla Firefox version prior to 3.0.14 on Linux.");
  script_tag(name:"insight", value:"- Multiple errors in the browser and JavaScript engines can be exploited
    to corrupt memory.

  - The warning dialog displayed when adding or removing security modules
    via 'pkcs11.addmodule' or 'pkcs11.deletemodule' does not contain enough
    information. This can be exploited to potentially trick a user into
    installing a malicious PKCS11 module.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.14 or later.");
  script_tag(name:"summary", value:"Firefox browser is prone to multiple Denial of Service vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Linux/Ver");
if(!ffVer)
  exit(0);

if(version_is_less(version:ffVer, test_version:"3.0.14")){
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"3.0.14");
  security_message(port: 0, data: report);
}
