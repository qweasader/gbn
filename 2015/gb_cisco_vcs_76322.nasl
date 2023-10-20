# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:telepresence_video_communication_server_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105335");
  script_cve_id("CVE-2015-4303", "CVE-2015-4316", "CVE-2015-4317", "CVE-2015-4318", "CVE-2015-4319", "CVE-2015-4320");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco TelePresence Video Communication Server (VCS) Multiple Vulnerabilities");

  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCuv40528");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76326");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76347");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76366");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76353");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76351");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76350");
  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCuv12333");
  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCuv40396");
  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCuv40469");
  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCuv12338");
  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCuv12340");

  script_tag(name:"summary", value:"Cisco TelePresence Video Communication Server Expressway is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Cisco TelePresence Video Communication Server (VCS) Command Injection

  A vulnerability in the web framework in the Cisco TelePresence Video Communication Server (VCS)
  could allow an authenticated, remote attacker to inject arbitrary commands that are executed user
  privilege ''nobody''.

  - Expressway user creds can be changed without providing current password

  A vulnerability in the Password Change functionality in the Administrative Web Interface of the
  Cisco TelePresence Video Communication Server (VCS) Expressway could allow an authenticated,
  remote attacker to make unauthorized changes to user passwords.

  - Password hashes are recorded to the Expressway Configuration Log

  A vulnerability in Configuration Log File of the Cisco TelePresence Video Communication Server
  (VCS) Expressway could allow an authenticated, remote attacker to obtain sensitive information
  stored on an affected system.

  - SIP Proxy-Authorization user not checked against phone line

  A vulnerability in of the Cisco TelePresence Video Communication Server (VCS) Expressway could
  allow an authenticated, remote attacker to falsely register their Mobile and Remote Access (MRA)
  endpoint.

  - XCP ConnectionManager segfaults on malformed auth message

  A vulnerability in the Cisco TelePresence Video Communication Server (VCS) Expressway could allow
  an unauthenticated, remote attacker to cause a denial of service (DoS) condition.

  - Traffic Server segfault on memcpy() from malformed GET request

  A vulnerability in the Cisco TelePresence Video Communication Server (VCS) Expressway could allow
  an unauthenticated, remote attacker to cause a denial of service (DoS) condition.

  These issues are being tracked by Cisco BugId:

  - CSCuv40528

  - CSCuv12333

  - CSCuv40396

  - CSCuv40469

  - CSCuv12338

  - CSCuv12340");

  script_tag(name:"affected", value:"Cisco TelePresence Video Communication Server Expressway
  X8.5.2.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-08-27 15:44:02 +0200 (Thu, 27 Aug 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_vcs_detect.nasl", "gb_cisco_vcs_ssh_detect.nasl");
  script_mandatory_keys("cisco_vcs/installed");

  exit(0);
}

include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version =~ "^8\.5\.2($|[^0-9])" ) {
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     Ask the vendor\n';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
