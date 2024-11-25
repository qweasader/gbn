# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dboss:diskboss_enterprise";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107125");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2017-01-17 16:11:25 +0530 (Tue, 17 Jan 2017)");
  script_name("DiskBoss Enterprise Server < 9.0 POST Buffer Overflow Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_diskboss_enterprise_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Disk/Boss/Enterprise/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41003/");

  script_tag(name:"summary", value:"DiskBoss Enterprise is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of
  web requests passed via POST request.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to elevate privileges from any account type and execute code.");

  script_tag(name:"affected", value:"DiskBoss Enterprise v7.5.12");

  script_tag(name:"solution", value:"Update to version 9.0 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!dbossPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dbossVer = get_app_version(cpe:CPE, port:dbossPort)){
  exit(0);
}

if(version_in_range(version:dbossVer, test_version: "7.0.0", test_version2:"7.5.12")){
  report = report_fixed_ver(installed_version:dbossVer, fixed_version:"9.0");
  security_message(data:report, port:dbossPort);
  exit(0);
}

exit(99);
