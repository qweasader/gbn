# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

#  Ref:  Jeroen van Wolffelaar <jeroen@wolffelaar.nl>
CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14343");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10969");
  script_cve_id("CVE-2004-0457");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MySQL mysqlhotcopy script insecure temporary file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Databases");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed");
  script_tag(name:"solution", value:"Upgrade to the latest version of MySQL 4.0.21 or newer");
  script_tag(name:"summary", value:"You are running a version of MySQL which is older than version 4.0.21.

mysqlhotcopy is reported to contain an insecure temporary file creation
vulnerability.

The result of this is that temporary files created by the application may
use predictable filenames.

A local attacker may also possibly exploit this vulnerability to execute
symbolic link file overwrite attacks.

*** Note : this vulnerability is local only");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!r = get_app_version(cpe:CPE, port:port))exit(0);

if(ereg(pattern:"3\.|4\.0\.([0-9]|1[0-9]|20)[^0-9]", string:r))security_message(port);

