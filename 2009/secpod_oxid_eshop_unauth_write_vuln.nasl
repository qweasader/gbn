# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oxid:eshop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900935");
  script_version("2023-08-04T05:06:23+0000");
  script_tag(name:"last_modification", value:"2023-08-04 05:06:23 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2009-3113");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OXID eShop Community Edition 4.x <= 4.1.1 Unauthorized Write Access Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_oxid_eshop_http_detect.nasl");
  script_mandatory_keys("oxid_eshop/detected");

  script_tag(name:"summary", value:"OXID eShop Community Edition is prone to unauthorized access
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"User supplied data passed to and unspecified variable is not
  sanitised before processing.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain
  unauthorized write access to product reviews via specially crafted URLs.");

  script_tag(name:"affected", value:"OXID eShop Community Edition version 4.x through 4.1.1");

  script_tag(name:"solution", value:"Upgrade to version 4.1.2 or later.");

  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/385007.php");
  script_xref(name:"URL", value:"http://www.oxidforge.org/wiki/Security_bulletins/2009-002");

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

if (version_in_range(version:version, test_version:"4.0", test_version2:"4.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
