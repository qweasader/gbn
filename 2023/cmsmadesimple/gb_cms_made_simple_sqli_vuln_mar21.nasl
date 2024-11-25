# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170465");
  script_version("2024-05-16T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"creation_date", value:"2023-05-12 19:34:45 +0000 (Fri, 12 May 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-15 16:07:00 +0000 (Mon, 15 May 2023)");

  script_cve_id("CVE-2021-28999");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("CMS Made Simple <= 2.2.16 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cms_made_simple_http_detect.nasl");
  script_mandatory_keys("cmsmadesimple/detected");

  script_tag(name:"summary", value:"CMS Made Simple is prone to an SQL injection (SQLi)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SQL Injection vulnerability in CMS Made Simple allows remote
  attackers to execute arbitrary commands via the m1_sortby parameter to
  modules/News/function.admin_articlestab.php.");

  script_tag(name:"affected", value:"CMS Made Simple version 2.2.16 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_xref(name:"URL", value:"https://github.com/beerpwn/CVE/blob/master/cms_made_simple_2021/sqli_order_by/CMS-MS-SQLi-report.md");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2021/Mar/49");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "2.2.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
