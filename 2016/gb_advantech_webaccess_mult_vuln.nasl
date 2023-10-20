# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
CPE = "cpe:/a:advantech:advantech_webaccess";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807033");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2015-3948", "CVE-2015-3943", "CVE-2015-3946", "CVE-2015-3947",
                "CVE-2015-6467", "CVE-2016-0851", "CVE-2016-0852", "CVE-2016-0853",
                "CVE-2016-0854", "CVE-2016-0855", "CVE-2016-0856", "CVE-2016-0857",
                "CVE-2016-0858", "CVE-2016-0859", "CVE-2016-0860");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:18:00 +0000 (Sat, 03 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-01-22 10:47:51 +0530 (Fri, 22 Jan 2016)");
  script_name("Advantech WebAccess Multiple Vulnerabilities Jan16");

  script_tag(name:"summary", value:"Advantech WebAccess is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The web server does not filter user input correctly.

  - Email project accounts are stored in clear text.

  - The web server accepts commands via specific scripts that imitate trusted
    accounts.

  - The Web server settings, accounts, and projects may be modified through
    scripted commands.

  - WebAccess can be made to run remote code through the use of a browser
    plug-in.

  - The software reads or writes to a buffer using an index or pointer that
    references a memory location after the end of the buffer.

  - Normal and remote users have access to files and folders that only
    administrators should be allowed to access.

  - Unrestricted file upload vulnerability.

  - Insufficient sanitization of filenames containing directory traversal
    sequences.

  - Multiple stack-based buffer overflows.

  - Multiple heap-based buffer overflows.

  - Integer overflow in the Kernel service.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attacker to upload, create, or delete arbitrary files on the target
  system, deny access to valid users and remotely execute arbitrary code.");

  script_tag(name:"affected", value:"Advantech WebAccess versions before 8.1");

  script_tag(name:"solution", value:"Upgrade to Advantech WebAccess version
  8.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-014-01");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_advantech_webaccess_consolidation.nasl");
  script_mandatory_keys("advantech/webaccess/detected");
  exit(0);
}

include( "version_func.inc" );
include( "host_details.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port ) )
  exit( 0 );

path = infos["location"];
vers = infos["version"];

if( version_is_less( version: vers, test_version: "8.1" ) ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: "8.1", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}
exit( 99 );
