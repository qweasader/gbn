# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803668");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2012-4192", "CVE-2012-4193");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-07-12 12:36:48 +0530 (Fri, 12 Jul 2013)");
  script_name("Mozilla Thunderbird Security Bypass Vulnerabilities - Oct 12 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50856");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55889");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50935");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-89.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to bypass the Same Origin Policy
  and read the properties of a Location object via a crafted web site.");
  script_tag(name:"affected", value:"Thunderbird versions before 16.0.1 on Windows");
  script_tag(name:"insight", value:"Security wrappers are unwrapped without doing a security check in
  defaultValue(). This can allow for improper access to the Location object.");
  script_tag(name:"solution", value:"Upgrade to Thunderbird version 16.0.1 or later.");
  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Thunderbird/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"16.0")){
    report = report_fixed_ver(installed_version:vers, fixed_version:"16.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
