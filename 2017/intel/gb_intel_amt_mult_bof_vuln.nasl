# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:intel:active_management_technology_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812222");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2017-5711", "CVE-2017-5712");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-22 16:18:00 +0000 (Mon, 22 May 2023)");
  script_tag(name:"creation_date", value:"2017-11-22 13:16:37 +0530 (Wed, 22 Nov 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Intel Active Management Technology Multiple Buffer Overflow Vulnerabilities");

  script_tag(name:"summary", value:"Intel Active Management Technology is prone to multiple buffer overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple unspecified
  buffer overflow errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code with AMT execution privilege.");

  script_tag(name:"affected", value:"Intel AMT for Intel ME Firmware versions
  8.x, 9.x, 10.x, 11.0.x.x, 11.5.x.x, 11.6.x.x, 11.7.x.x, 11.10.x.x and 11.20.x.x.");

  script_tag(name:"solution", value:"Upgrade Intel Active Management Technology to
  the appropriate Intel ME firmware version as described in the references.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://thehackernews.com/2017/11/intel-chipset-flaws.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00086.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_intel_amt_webui_detect.nasl");
  script_mandatory_keys("intel_amt/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^(8|9|10|(11\.(0|5|6|7|10|20)))") {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
