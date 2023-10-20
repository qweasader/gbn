# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:telepresence_video_communication_server_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105723");
  script_cve_id("CVE-2016-1400");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco Video Communication Server Session Initiation Protocol Packet Processing Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160516-vcs");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to a malformed SIP header message. An attacker could exploit this vulnerability by manipulating the SIP URI. An exploit could allow the attacker to cause a disruption of service to the application.");

  script_tag(name:"solution", value:"Update to version X8.7.2 or higher.");
  script_tag(name:"summary", value:"A vulnerability in the Session Initiation Protocol (SIP) implementation of the Cisco Video Communications Server (VCS) could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition.");
  script_tag(name:"affected", value:"Cisco TelePresence VCS X8.x releases prior to X8.7.2 are vulnerable.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-01 03:05:00 +0000 (Thu, 01 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-05-17 15:13:01 +0200 (Tue, 17 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_vcs_detect.nasl", "gb_cisco_vcs_ssh_detect.nasl");
  script_mandatory_keys("cisco_vcs/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version =~ "^8\." )
{
  if( version_is_less( version:version, test_version:"8.7.2" ) )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version:"X8.7.2" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
