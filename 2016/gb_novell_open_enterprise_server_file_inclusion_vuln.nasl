# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:novell:open_enterprise_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809480");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-5763");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:29:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-11-25 10:29:09 +0530 (Fri, 25 Nov 2016)");
  script_name("Novell Open Enterprise Server File Inclusion Vulnerability");

  script_tag(name:"summary", value:"Novell Open Enterprise Server is prone to a file inclusion vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to 'namuseradd -a' creating
  incorrectly named der files in '/var/lib/novell-lum'.");

  script_tag(name:"impact", value:"Successful exploitation will allow authenticated
  remote attackers to gain unauthorized file access and perform modification.");

  script_tag(name:"affected", value:"Novell OES2015 SP1 before Scheduled Maintenance Update 10992,

  Novell OES2015 before Scheduled Maintenance Update 10990,

  Novell OES11 SP3 before Scheduled Maintenance Update 10991,

  Novell OES11 SP2 before Scheduled Maintenance Update 10989.");

  script_tag(name:"solution", value:"Upgrade to Novell OES2015 SP1 Scheduled
  Maintenance Update 10992, OES2015 Scheduled Maintenance Update 10990,
  OES11 SP3 Scheduled Maintenance Update 10991, OES11 SP2 Scheduled Maintenance
  Update 10989 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://download.novell.com/Download?buildid=dfqmrymc0Rg~");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94348");
  script_xref(name:"URL", value:"http://download.novell.com/Download?buildid=s9_RxhgC8KU~");

  script_family("Web application abuses");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_novell_open_enterprise_server_remote_detect.nasl");
  script_mandatory_keys("Novell/Open/Enterprise/Server/Installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!novellPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!novellVer = get_app_version(cpe:CPE, port:novellPort)){
  exit(0);
}

if((novellVer =~ "^11\." && version_is_less_equal(version:novellVer, test_version:"11.SP3")) ||
   (novellVer =~ "^2015\." && version_is_less_equal(version:novellVer, test_version:"2015.SP1"))){
  report = report_fixed_ver(installed_version:novellVer, fixed_version:"Upgrade to Appropriate Scheduled Maintenance Update");
  security_message(data:report, port:novellPort);
  exit(0);
}
