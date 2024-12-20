# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813915");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2018-3775");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-27 16:45:00 +0000 (Mon, 27 Feb 2023)");
  script_tag(name:"creation_date", value:"2018-08-20 17:29:50 +0530 (Mon, 20 Aug 2018)");
  script_name("Nextcloud Server Security Bypass Vulnerability (Aug 2018)");

  script_tag(name:"summary", value:"Nextcloud Server is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper authentication
  of the second factor challenge.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to bypass the second factor validation completely.");

  script_tag(name:"affected", value:"Nextcloud Server before 12.0.3.");

  script_tag(name:"solution", value:"Upgrade to Nextcloud Server version 12.0.3
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=NC-SA-2018-007");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("nextcloud/installed", "Host/runs_unixoide");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"12.0.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"12.0.3", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
