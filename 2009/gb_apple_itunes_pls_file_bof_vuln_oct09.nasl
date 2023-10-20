# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801105");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-01 12:15:29 +0200 (Thu, 01 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2817");
  script_name("Apple iTunes '.pls' Files Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT3884");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36478");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2009/Sep/msg00006.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code within
  the context of the affected application, failed exploit attempts will result in
  a denial of service condition.");

  script_tag(name:"affected", value:"Apple iTunes version prior to 9.0.1 on Windows.");

  script_tag(name:"insight", value:"The flaw exists in the handling of specially crafted '.pls' files. It fails
  to bounds-check user-supplied data before copying it into an insufficiently sized buffer.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Apple iTunes Version 9.0.1.");

  script_tag(name:"summary", value:"Apple iTunes is prone to a buffer overflow vulnerability.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"9.0.1.8" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"9.0.1.8", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );