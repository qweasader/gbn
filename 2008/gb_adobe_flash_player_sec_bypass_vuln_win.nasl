# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800027");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-10-16 18:25:33 +0200 (Thu, 16 Oct 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-6243", "CVE-2008-3873", "CVE-2007-4324",
                "CVE-2008-4401", "CVE-2008-4503");
  script_name("Adobe Flash Player Multiple Security Bypass Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32163/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31117");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb08-18.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa08-08.html");
  script_xref(name:"URL", value:"http://blogs.adobe.com/psirt/2008/10/clickjacking_security_advisory.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");

  script_tag(name:"impact", value:"Successful attack could allow malicious people to bypass certain
  security restrictions or manipulate certain data.");

  script_tag(name:"affected", value:"Adobe Flash Player 9.x - 9.0.124.0 on Windows.");

  script_tag(name:"insight", value:"The flaws are due to:

  - a design error in the application allows access to the system's
    camera and microphone by tricking the user into clicking Flash Player
    access control dialogs disguised as normal graphical elements.

  - FileReference.browse() and FileReference.download() methods can be
    called without user interaction and can potentially be used
    to trick a user into downloading or uploading files.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player 10.0.12.36.");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple security bypass vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_in_range( version:vers, test_version:"9.0", test_version2:"9.0.124.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.0.12.36", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );