# SPDX-FileCopyrightText: 2005 StrongHoldNet
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11378");
  script_version("2023-08-01T13:29:10+0000");
  script_cve_id("CVE-2003-0150");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_name("MySQL < 3.23.56 'mysqld' Privilege Escalation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 StrongHoldNet");
  script_family("Databases");
  script_dependencies("find_service.nasl", "mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7052");

  script_tag(name:"summary", value:"MySQL is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability by creating a
  DATADIR/my.cnf that includes the line 'user=root' under the '[mysqld]' option section.

  When the mysqld service is executed, it will run as the root user instead of the default user.");

  script_tag(name:"solution", value:"Update to version 3.23.56 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!ver = get_app_version(cpe:CPE, port:port))
  exit(0);

if(ereg(pattern:"3\.(([0-9]\..*)|(1[0-9]\..*)|(2(([0-2]\..*)|3\.(([0-9]$)|([0-4][0-9])|(5[0-5])))))",
        string:ver)) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"3.23.56");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
