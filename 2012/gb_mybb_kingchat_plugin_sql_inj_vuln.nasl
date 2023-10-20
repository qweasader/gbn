# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:mybb:mybb';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803124");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-12-04 18:28:42 +0530 (Tue, 04 Dec 2012)");
  script_name("MyBB KingChat Plugin SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/23105/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/118569/mybbkingchat-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("MyBB/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to compromise
  the application, access or modify data or exploit vulnerabilities in the
  underlying database.");
  script_tag(name:"affected", value:"MyBB kingchat Plugin version 0.5");
  script_tag(name:"insight", value:"The application fails to sufficiently sanitize user supplied
  input to the 'username' parameter in 'kingchat.php' before using it in an SQL
  query, which  allows attackers to execute arbitrary SQL commands in the context
  of an affected site.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"MyBB KingChat Plugin is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");


if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! tmpDir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if (tmpDir == "/") tmpDir = "";

foreach dir(make_list(tmpDir, tmpDir + "/Upload"))
{

  url = string(dir , "/kingchat.php?send=Red_Hat&username='SQL-INJECTION-TEST");

  if(http_vuln_check(port:port, url:url, pattern:"'SQL-INJECTION-TEST",
  extra_check: make_list("MyBB has experienced an internal SQL error",
             "SELECT", "FROM mybb_users WHERE username='")))
  {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
