# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803391");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2012-4191");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-10-15 17:43:07 +0530 (Mon, 15 Oct 2012)");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Mozilla Seamonkey 'WebSockets' Denial of Service Vulnerability (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/50856");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55889");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50935");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-88.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Seamonkey/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service
  (memory corruption and application crash) or possibly execute arbitrary code via unspecified vectors.");

  script_tag(name:"affected", value:"SeaMonkey versions before 2.13.1 on Windows.");

  script_tag(name:"insight", value:"Error in the WebSockets implementation, allows remote attackers to cause a
  denial of service.");

  script_tag(name:"solution", value:"Upgrade to SeaMonkey version to 2.13.1 or later.");

  script_tag(name:"summary", value:"Mozilla Seamonkey is prone to multiple vulnerabilities.");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Seamonkey/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"2.13.1"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"2.13.1");
    security_message(port: 0, data: report);
    exit(0);
  }
}
