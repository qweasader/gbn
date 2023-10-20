# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802830");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2011-3388", "CVE-2011-3389");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-04-06 12:13:30 +0530 (Fri, 06 Apr 2012)");
  script_name("Opera Extended Validation Information Disclosure Vulnerabilities (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45791");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49388");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1025997");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1000/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to steal sensitive security
  information.");
  script_tag(name:"affected", value:"Opera version before 11.51 on Linux");
  script_tag(name:"insight", value:"Multiple flaws are due to an error when loading content from trusted
  sources in an unspecified sequence that causes the address field and page
  information dialog to contain security information based on the trusted site
  and loading an insecure site to appear secure via unspecified actions related
  to Extended Validation.");
  script_tag(name:"solution", value:"Upgrade to Opera version 11.51 or later.");
  script_tag(name:"summary", value:"Opera is prone to information disclosure vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"11.51")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"11.51");
  security_message(port:0, data:report);
}
