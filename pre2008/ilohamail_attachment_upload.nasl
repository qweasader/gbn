# SPDX-FileCopyrightText: 2004 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ilohamail:ilohamail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14632");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_xref(name:"OSVDB", value:"7334");
  script_name("IlohaMail Attachment Upload Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("ilohamail_detect.nasl");
  script_mandatory_keys("ilohamail/detected");

  script_xref(name:"URL", value:"http://ilohamail.org/forum/view_thread.php?topic_id=5&id=561");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6740");

  script_tag(name:"solution", value:"Upgrade to IlohaMail version 0.7.9 or later.");

  script_tag(name:"summary", value:"The target is running at least one instance of IlohaMail version
  0.7.9-RC2 or earlier. Such versions do not properly check the upload path for file attachments,
  which may allow an attacker to place a file on the target in a location writable by the web user
  if the file-based backend is in use.

  ***** The Scanner has determined the vulnerability exists on the target

  ***** simply by looking at the version number of IlohaMail

  ***** installed there.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit(0);
vers = infos['version'];
path = infos['location'];

if( vers =~ "^0\.([0-6].*|7\.([0-8](-Devel)?|9-.+)$)" ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.7.9", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );