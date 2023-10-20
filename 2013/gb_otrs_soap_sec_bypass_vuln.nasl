# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803947");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2008-1515");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74733");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-09-28 13:08:01 +0530 (Sat, 28 Sep 2013)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OTRS SOAP Security Bypass Vulnerability");

  script_tag(name:"summary", value:"OTRS (Open Ticket Request System) is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in SOAP interface which
  fails to properly validate user credentials before performing certain actions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to read and modify objects via the OTRS SOAP interface.");

  script_tag(name:"affected", value:"OTRS (Open Ticket Request System)
  version 2.1.0 before 2.1.8 and 2.2.0 before 2.2.6");

  script_tag(name:"solution", value:"Upgrade to OTRS version 2.1.8 or 2.2.6
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!otrsport = get_app_port(cpe:CPE)){
  exit(0);
}

if(!otrsVer = get_app_version(cpe:CPE, port:otrsport)){
  exit(0);
}

if(otrsVer =~ "^2\.(1|2)")
{
  if(version_in_range(version:otrsVer, test_version:"2.1.0", test_version2:"2.1.7")||
     version_in_range(version:otrsVer, test_version:"2.2.0", test_version2:"2.2.5"))
  {
    security_message(port:otrsport);
    exit(0);
  }
}
