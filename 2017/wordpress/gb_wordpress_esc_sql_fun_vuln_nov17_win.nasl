# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811887");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-16510");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-04 02:29:00 +0000 (Sun, 04 Feb 2018)");
  script_tag(name:"creation_date", value:"2017-11-02 10:53:57 +0530 (Thu, 02 Nov 2017)");
  script_name("WordPress 'esc_sql' Function SQL Injection Vulnerability - Nov 2017 (Windows)");

  script_tag(name:"summary", value:"WordPress is prone to an SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because '$wpdb->prepare'
  function can create unexpected and unsafe queries.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary commands.");

  script_tag(name:"affected", value:"WordPress versions 4.8.2 and earlier");

  script_tag(name:"solution", value:"Update to WordPress version 4.8.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://wordpress.org/news/2017/10/wordpress-4-8-3-security-release");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wordPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!vers = get_app_version(cpe:CPE, port:wordPort)){
  exit(0);
}

if(version_is_less(version:vers, test_version:"4.8.3"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.8.3");
  security_message(data:report, port:wordPort);
  exit(0);
}
exit(0);
