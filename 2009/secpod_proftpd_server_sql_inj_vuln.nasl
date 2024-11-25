# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:proftpd:proftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900507");
  script_version("2024-03-04T05:10:24+0000");
  script_tag(name:"last_modification", value:"2024-03-04 05:10:24 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0542", "CVE-2009-0543");
  script_name("ProFTPD Server SQL Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("FTP");
  script_dependencies("secpod_proftpd_server_detect.nasl");
  script_mandatory_keys("ProFTPD/Installed");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8037");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33722");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/500833/100/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/500851/100/0/threaded");

  script_tag(name:"summary", value:"ProFTPD Server is prone to remote SQL Injection vulnerability.");

  script_tag(name:"insight", value:"This flaw occurs because the server performs improper input sanitising,

  - when a %(percent) character is passed in the username, a single quote
  (') gets introduced during variable substitution by mod_sql and this
  eventually allows for an SQL injection during login.

  - when NLS support is enabled, a flaw in variable substitution feature in
  mod_sql_mysql and mod_sql_postgres may allow an attacker to bypass
  SQL injection protection mechanisms via invalid, encoded multibyte characters.");

  script_tag(name:"affected", value:"ProFTPD Server version 1.3.1 through 1.3.2rc2.");

  script_tag(name:"solution", value:"Upgrade to the latest version 1.3.2rc3.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  SQL commands, thus gaining access to random user accounts.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"1.3.1", test_version2:"1.3.2.rc2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.3.2rc3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
