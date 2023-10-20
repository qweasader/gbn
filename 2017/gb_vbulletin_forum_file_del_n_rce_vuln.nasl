# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812354");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-17672");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-02 16:29:00 +0000 (Tue, 02 Jan 2018)");
  script_tag(name:"creation_date", value:"2017-12-18 18:33:37 +0530 (Mon, 18 Dec 2017)");

  script_name("vBulletin Forum Arbitrary File Deletion And Remote Code Execution Vulnerabilities");

  script_tag(name:"summary", value:"vBulletin is prone to arbitrary file deletion and remote code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Unsafe usage of PHP's unserialize function in vB_Library_Template's cacheTemplates function, which is a
  publicly exposed API.

  - A deserialization vulnerability.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to execute arbitrary code execution and arbitrary file
  deletion on the affected system.");

  script_tag(name:"affected", value:"VBulletin versions through 5.3.4");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
  a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3569");
  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3573");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("vbulletin_detect.nasl");
  script_mandatory_keys("vbulletin/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(version_is_less_equal(version:vers, test_version:"5.3.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"NoneAvailable", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
