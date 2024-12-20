# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:soplanning:soplanning";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112035");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2014-8673", "CVE-2014-8674", "CVE-2014-8675", "CVE-2014-8676", "CVE-2014-8677");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-08 15:54:00 +0000 (Wed, 08 Jan 2020)");
  script_tag(name:"creation_date", value:"2017-09-04 12:34:59 +0200 (Mon, 04 Sep 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Simple Online Planning < 1.33 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Simple Online Planning is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"SOPlanning version 1.32 and earlier.");

  script_tag(name:"solution", value:"Update to version 1.33 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jul/44");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75726");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_soplanning_detect.nasl");
  script_mandatory_keys("soplanning/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!vers = get_app_version(cpe:CPE, port:port)) exit(0);

if(version_is_less_equal(version:vers, test_version:"1.32")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.33");
  security_message(data:report, port:port);
  exit(0);
}
exit(99);
