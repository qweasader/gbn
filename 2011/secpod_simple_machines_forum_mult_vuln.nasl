# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:simplemachines:smf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902446");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_cve_id("CVE-2011-1127", "CVE-2011-1128", "CVE-2011-1129",
                "CVE-2011-1130", "CVE-2011-1131");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Simple Machines Forum Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2011/03/02/4");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48388");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2011/02/22/17");
  script_xref(name:"URL", value:"http://www.simplemachines.org/community/index.php?topic=421547.0");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_simple_machines_forum_detect.nasl");
  script_mandatory_keys("SMF/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain access or cause a
  denial of service or to conduct SQL injection attacks, obtain sensitive information.");

  script_tag(name:"affected", value:"Simple Machines Forum (SMF) before 1.1.13 and 2.x before 2.0 RC5.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in 'SSI.php', it does not properly restrict guest access.

  - An error in loadUserSettings function in 'Load.php', it does not properly
    handle invalid login attempts.

  - An error in EditNews function in 'ManageNews.php', which allow users to
    inject arbitrary web script or HTML via a save_items action.

  - An error in cleanRequest function in 'QueryString.php' and the
    constructPageIndex function 'in Subs.php'.

  - An error in PlushSearch2 function in 'Search.php', allow remote attackers
    to obtain sensitive information via a search.");

  script_tag(name:"summary", value:"Simple Machines Forum is prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Apply the patch or upgrade to version 1.1.13 or 2.0 RC5.");

  script_xref(name:"URL", value:"http://custom.simplemachines.org/mods/downloads/smf_patch_2.0-RC4_security.zip");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! ver = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:ver, test_version:"2.0.0", test_version2:"2.0.99" ) )
  exit( 0 );

if( version_is_less( version:ver, test_version:"1.1.3" ) ||
    version_in_range( version:ver, test_version:"2.0.RC", test_version2:"2.0.RC4" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"1.1.13 or 2.0 RC5" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
