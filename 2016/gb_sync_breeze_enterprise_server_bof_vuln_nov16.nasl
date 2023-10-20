# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:flexense:syncbreeze";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809481");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-11-29 12:58:33 +0530 (Tue, 29 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Sync Breeze Enterprise Server Buffer Overflow Vulnerability - Nov16");

  script_tag(name:"summary", value:"Sync Breeze Enterprise Server is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing
  web requests and can be exploited to cause a buffer overflow via an overly long
  string passed to 'Login' request.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.");

  script_tag(name:"affected", value:"Sync Breeze Enterprise version 9.1.16
  and earlier.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.syncbreeze.com");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40831");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_sync_breeze_enterprise_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("flexsense_syncbreeze/detected", "Host/runs_windows");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!syncPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!syncVer = get_app_version(cpe:CPE, port:syncPort)){
  exit(0);
}

if(version_is_less_equal(version:syncVer, test_version:"9.1.16"))
{
  report = report_fixed_ver(installed_version:syncVer, fixed_version:"None Available");
  security_message(data:report, port:syncPort);
  exit(0);
}
