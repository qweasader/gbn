# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808148");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2012-6619");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-06-07 10:46:58 +0530 (Tue, 07 Jun 2016)");
  script_name("MongoDB BSON Object Information Disclosure Vulnerability (Linux)");

  script_tag(name:"summary", value:"MongoDB is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in the application which
  fails to properly validate incorrect length of an BSON object.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to access sensitive information stored in the server process
  memory.");

  script_tag(name:"affected", value:"MongoDB version prior to 2.3.2 on Linux");

  script_tag(name:"solution", value:"Upgrade to MongoDB version 2.3.2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-7769");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64687");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_family("Databases");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/mongodb", 27017);
  script_mandatory_keys("mongodb/installed", "Host/runs_unixoide");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");


if(!mbPort = get_app_port(cpe:CPE))exit(0);

if(!ver = get_app_version(cpe:CPE, port:mbPort))exit(0);

if(version_is_less(version:ver, test_version:"2.3.2"))
{
  report = report_fixed_ver(installed_version:ver, fixed_version:"2.3.2");
  security_message(data:report, port:mbPort);
  exit(0);
}
