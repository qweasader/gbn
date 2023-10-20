# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:messaging_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812359");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-15532");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 19:43:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2017-12-21 16:31:51 +0530 (Thu, 21 Dec 2017)");

  script_name("Symantec Messaging Gateway Directory Traversal Vulnerability (SYM17-016)");

  script_tag(name:"summary", value:"Symantec Messaging Gateway is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error which makes
  possible to access arbitrary files and directories stored on the file system
  including application source code or configuration and critical system files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct a path traversal attack.");

  script_tag(name:"affected", value:"Symantec Messaging Gateway (SMG) before 10.6.4");

  script_tag(name:"solution", value:"Upgrade to Symantec Messaging Gateway (SMG)
  10.6.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20171220_00");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102096");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_symantec_messaging_gateway_detect.nasl");
  script_mandatory_keys("symantec_smg/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!version = get_app_version( cpe:CPE, nofork: TRUE))
  exit(0);

if(version_is_less(version:version, test_version:"10.6.4")) {
  report = report_fixed_ver(installed_version:version, fixed_version:'10.6.4');
  security_message(port: 0, data:report);
  exit(0);
}

exit(0);
