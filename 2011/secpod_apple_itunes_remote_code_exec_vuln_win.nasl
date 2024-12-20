# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902638");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2008-3434");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-11-28 15:07:07 +0530 (Mon, 28 Nov 2011)");
  script_name("Apple iTunes Remote Code Execution Vulnerability - Windows");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5030");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50672");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4981");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2011/Nov/msg00003.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the user running the affected application.");

  script_tag(name:"affected", value:"Apple iTunes version prior to 10.5.1 (10.5.1.42) on Windows.");

  script_tag(name:"insight", value:"The flaw is due to the improper verification of authenticity of
  updates, allows man-in-the-middle attack execute arbitrary code via a Trojan horse update.");

  script_tag(name:"solution", value:"Upgrade to Apple Apple iTunes version 10.5.1 or later.");

  script_tag(name:"summary", value:"Apple iTunes is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

## Apple iTunes version < 10.5.1 (10.5.1.42)
if( version_is_less( version:vers, test_version:"10.5.1.42" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.5.1.42", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
