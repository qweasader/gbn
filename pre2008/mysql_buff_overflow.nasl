# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14319");
  script_version("2023-08-03T05:05:16+0000");
  script_cve_id("CVE-2004-0836");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("MySQL < 4.0.21 Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Gain a shell remotely");
  script_dependencies("find_service.nasl", "mysql_version.nasl");
  script_mandatory_keys("MySQL/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10981");

  script_tag(name:"summary", value:"MySQL is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The MySQL version is vulnerable to a length overflow within it's
  mysql_real_connect() function.

  The overflow is due to an error in the processing of a return Domain (DNS) record.

  An attacker, exploiting this flaw, would need to control a DNS server which would be queried by
  the MySQL server.");

  script_tag(name:"impact", value:"A successful attack would give the attacker the ability to
  execute arbitrary code on the remote machine.");

  script_tag(name:"solution", value:"Update to version 4.0.21 or later.");

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

if(ereg(pattern:"([0-3]\.[0-9]\.[0-9]|4\.0\.([0-9]|1[0-9]|20)[^0-9])",
        string:ver)) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"4.0.21");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
