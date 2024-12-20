# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mongodb:mongodb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808147");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2015-1609");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-06-07 10:43:02 +0530 (Tue, 07 Jun 2016)");
  script_name("MongoDB BSON Message Handling Remote Denial-of-Service Vulnerability - Linux");

  script_tag(name:"summary", value:"MongoDB is prone to remote denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to error in mongod that is
  triggered when handling a specially crafted BSON message.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (application crash).");

  script_tag(name:"affected", value:"MongoDB version 2.4.12 and earlier,
  2.6.7 and earlier, and 3.0.0-rc8 on Linux");

  script_tag(name:"solution", value:"Upgrade to MongoDB version 2.4.13 or
  2.6.8 or 3.0.0-rc9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://www.mongodb.org/about/alerts/");
  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-17264");
  script_xref(name:"URL", value:"https://fortiguard.com/zeroday/FG-VD-15-012");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_unixoide");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!mongodbPort = get_app_port(cpe:CPE)) exit(0);

if(!ver = get_app_version(cpe:CPE, port:mongodbPort)) exit(0);

##Replace '-' by '.' in version
if("-rc" >< ver){
 mongodbversion = ereg_replace(pattern:"-", replace:".", string:ver);
}

if(mongodbversion)
{
  if(version_in_range(version:mongodbversion, test_version:"2.6", test_version2:"2.6.7"))
  {
    fix = "2.6.8";
    VULN = TRUE ;
  }

  else if(version_in_range(version:mongodbversion, test_version:"2.4", test_version2:"2.4.12"))
  {
    fix = "2.4.13";
    VULN = TRUE ;
  }

  else if(version_is_equal(version:mongodbversion, test_version:"3.0.0.rc8"))
  {
    fix = "3.0.0.rc9";
    VULN = TRUE ;
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:mongodbversion, fixed_version:fix);
    {
      security_message(data:report, port:mongodbPort);
      exit(0);
    }
  }
}
