# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cybozu:mailwise";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107163");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2017-05-11 12:30:22 +0200 (Thu, 11 May 2017)");
  script_cve_id("CVE-2016-4842", "CVE-2016-4844", "CVE-2016-4843", "CVE-2016-4841");

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-25 13:48:00 +0000 (Tue, 25 Apr 2017)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cybozu Mailwise < 5.4.0 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Cybozu Mailwise is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  information on when an email is read, conduct clickjacking attacks, obtain sensitive cookie
  information and inject arbitrary email headers.");

  script_tag(name:"affected", value:"Cybozu Mailwise versions prior to 5.4.0.");

  script_tag(name:"solution", value:"Update to version 5.4.0 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92460");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92459");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92461");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92462");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cybozu_products_http_detect.nasl");
  script_mandatory_keys("cybozu/mailwise/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"5.4.0")){
  report = report_fixed_ver(installed_version:version, fixed_version:"5.4.0", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
