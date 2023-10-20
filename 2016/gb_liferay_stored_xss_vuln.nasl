# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:liferay:liferay_portal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808707");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-3670");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-20 12:35:00 +0000 (Mon, 20 Jun 2016)");
  script_tag(name:"creation_date", value:"2016-08-01 13:53:02 +0530 (Mon, 01 Aug 2016)");

  script_name("Liferay Stored XSS Vulnerability");

  script_tag(name:"summary", value:"Liferay is prone to a stored cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation
  of user input in 'users.jsp' script.");

  script_tag(name:"impact", value:"Successfully exploitation will allows remote
  attackers to inject arbitrary web script or HTML via the FirstName field.");

  script_tag(name:"affected", value:"Liferay version before 7.0.0 CE RC1.");

  script_tag(name:"solution", value:"Update Liferay version 7.0.0 CE RC1
  and later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://labs.integrity.pt/advisories/cve-2016-3670/");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_liferay_detect.nasl");
  script_mandatory_keys("liferay/detected");
  script_xref(name:"URL", value:"https://issues.liferay.com/browse/LPS/component/10296");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"7.0.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"7.0.0", install_path: location);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
