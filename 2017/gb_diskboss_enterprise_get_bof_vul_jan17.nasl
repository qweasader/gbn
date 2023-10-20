# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dboss:diskboss_enterprise";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107124");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-01-17 16:11:25 +0530 (Tue, 17 Jan 2017)");
  script_name("DiskBoss Enterprise Server 'Get' Buffer Overflow Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_diskboss_enterprise_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Disk/Boss/Enterprise/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41079/");

  script_tag(name:"summary", value:"DiskBoss Enterprise is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of
  web requests passed via GET request.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to elevate privileges from any account type and execute code.");

  script_tag(name:"affected", value:"DiskBoss Enterprise v7.5.12 and v7.4.28.");

  script_tag(name:"solution", value:"Update to version 9.0 or above.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"7.0.0", test_version2:"7.4.28") ||
   version_in_range(version:vers, test_version:"7.5.0", test_version2:"7.5.12")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"9.0");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
