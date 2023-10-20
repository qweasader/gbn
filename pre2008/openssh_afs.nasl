# SPDX-FileCopyrightText: 2005 Thomas Reinke
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10954");
  script_version("2023-08-03T05:05:16+0000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4560");
  script_cve_id("CVE-2002-0575");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("OpenSSH AFS/Kerberos ticket/token passing");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Thomas Reinke");
  script_family("Gain a shell remotely");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_tag(name:"solution", value:"Upgrade to the latest version of OpenSSH");

  script_tag(name:"summary", value:"OpenSSH is prone to a buffer overflow vulnerability.");

  script_tag(name:"insight", value:"A buffer overflow exists in the daemon if AFS is enabled on the
  remote system, or if the options KerberosTgtPassing or AFSTokenPassing are enabled. Even in this
  scenario, the vulnerability may be avoided by enabling UsePrivilegeSeparation.");

  script_tag(name:"affected", value:"Versions prior to 2.9.9 are vulnerable to a remote root
  exploit. Versions prior to 3.2.1 are vulnerable to a local root exploit.");

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

if( version_is_less( version:vers, test_version:"3.2.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.2.1", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );