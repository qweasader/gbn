# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800493");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0040", "CVE-2010-0041", "CVE-2010-0042", "CVE-2010-0043",
                "CVE-2010-0044", "CVE-2010-0045", "CVE-2010-0046", "CVE-2010-0047",
                "CVE-2010-0048", "CVE-2010-0049", "CVE-2010-0050", "CVE-2010-0051",
                "CVE-2010-0052", "CVE-2010-0053", "CVE-2010-0054");
  script_name("Apple Safari Webkit Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4070");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38673");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38674");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38675");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38676");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38677");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38683");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38684");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38685");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38686");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38687");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38688");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38689");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38690");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38691");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38692");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2010/Mar/msg00000.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code, bypass
  security restrictions, sensitive information disclosure, and can cause other attacks.");

  script_tag(name:"affected", value:"Apple Safari version prior to 4.0.5 (5.31.22.7) on Windows.");

  script_tag(name:"insight", value:"Please see the references for more information about the vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 4.0.5.");

  script_tag(name:"summary", value:"Apple Safari Web Browser is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"5.31.22.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Safari 4.0.5 (5.31.22.7)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
