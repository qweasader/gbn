# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103503");
  script_cve_id("CVE-2012-0814");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_name("openssh-server Forced Command Handling Information Disclosure Vulnerability");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-06-28 11:05:31 +0200 (Thu, 28 Jun 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51702");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=657445");
  script_xref(name:"URL", value:"https://downloads.avaya.com/css/P8/documents/100161262");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"The auth_parse_options function in auth-options.c in sshd in
  OpenSSH before 5.7 provides debug messages containing authorized_keys command options, which
  allows remote authenticated users to obtain potentially sensitive information by reading these
  messages, as demonstrated by the shared user account required by Gitolite.

  NOTE: this can cross privilege boundaries because a user account may intentionally have no shell
  or filesystem access, and therefore may have no nupported way to read an authorized_keys file in
  its own home directory.");

  script_tag(name:"affected", value:"OpenSSH before 5.7.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"5.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.7", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );