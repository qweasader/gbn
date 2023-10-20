# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803140");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2012-6470", "CVE-2012-6471", "CVE-2012-6472");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-01-07 14:21:28 +0530 (Mon, 07 Jan 2013)");
  script_name("Opera Multiple Vulnerabilities-01 Jan13 (Linux)");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1039/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56788");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56984");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1038/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1040/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unified/1212/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker crash the browser leading to
  denial of service, execute the arbitrary code or spoofing the address.");

  script_tag(name:"affected", value:"Opera version before 12.12 on Linux");

  script_tag(name:"insight", value:"- Malformed GIF images could allow execution of arbitrary code.

  - Repeated attempts to access a target site can trigger address field
    spoofing.

  - Private data can be disclosed to other computer users, or be modified
    by them.");

  script_tag(name:"solution", value:"Upgrade to Opera version 12.12 or later.");

  script_tag(name:"summary", value:"Opera is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"12.12")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"12.12");
  security_message(port: 0, data: report);
}
