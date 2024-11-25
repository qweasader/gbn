# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.107340");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2018-09-10 15:43:15 +0200 (Mon, 10 Sep 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Infoblox NetMRI Administration Shell Escape and Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_netmri_detect.nasl");
  script_mandatory_keys("netMRI/detected");

  script_tag(name:"summary", value:"The administrative shell of Infoblox NetMRI 7.1.2 through 7.1.4 is prone to a
  shell escape and privilege escalation vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An authenticated user can escape the management shell and subsequently
  escalate to root via insecure file ownership and sudo permissions.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to gain complete control over
  the target system.");

  script_tag(name:"affected", value:"Infoblox NetMRI version 7.1.2 through 7.1.4. Other versions might be affected
  as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.korelogic.com/Resources/Advisories/KL-001-2017-017.txt");

  exit(0);
}

CPE = "cpe:/a:infoblox:netmri";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( port:port, cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos['version'];
path = infos['location'];

if( version_in_range( version:version, test_version:"7.1.2", test_version2:"7.1.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:path );
  security_message( data:report, port:port);
  exit( 0 );
}
exit( 99 );
