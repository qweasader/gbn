# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803405");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-02-12 13:17:51 +0530 (Tue, 12 Feb 2013)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2013-0633", "CVE-2013-0634");
  script_name("Adobe Flash Player Multiple Vulnerabilities -01 Feb13 (Mac OS X)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52116");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57787");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57788");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/81866");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-04.html");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause buffer
  overflow, remote code execution, and corrupt system memory.");

  script_tag(name:"affected", value:"Adobe Flash Player prior to 10.3.183.51 and 11.x prior to 11.5.502.149
  on Mac OS X");

  script_tag(name:"insight", value:"Error while processing multiple references to an unspecified object which can
  be exploited by tricking the user to accessing a malicious crafted SWF file.");

  script_tag(name:"solution", value:"Update to version 11.5.502.149 or later.");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Adobe/Flash/Player/MacOSX/Version");
if(vers =~ "^[0-9]+\.")
{
  if(version_is_less(version:vers, test_version:"10.3.183.51") ||
     version_in_range(version:vers, test_version:"11.0", test_version2:"11.5.502.148"))
  {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"< 10.3.183.51, 11.0 - 11.5.502.148");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
