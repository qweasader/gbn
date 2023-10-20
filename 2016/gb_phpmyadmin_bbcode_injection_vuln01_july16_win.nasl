# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808244");
  script_version("2023-10-17T05:05:34+0000");
  script_cve_id("CVE-2016-5701");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-07-04 14:45:45 +0530 (Mon, 04 Jul 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("phpMyAdmin BBCode Injection Vulnerability -01 July16 (Windows)");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a BBCode injection attack.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient validation
  of user supplied input via crafted URI to 'setup/frames/index.inc.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct BBCode injection attacks against HTTP sessions.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.0.10.x before 4.0.10.16,
  4.4.15.x before 4.4.15.7, and 4.6.x before 4.6.3 on Windows.");

  script_tag(name:"solution", value:"Upgrade to phpMyAdmin version 4.0.10.16 or
  4.4.15.7 or 4.6.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-17");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_windows");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!phpPort = get_app_port(cpe:CPE)) exit(0);

if(!phpVer = get_app_version(cpe:CPE, port:phpPort)) exit(0);

if(phpVer =~ "^(4\.0\.10)")
{
  if(version_is_less(version:phpVer, test_version:"4.0.10.16"))
  {
    fix = "4.0.10.16";
    VULN = TRUE;
  }
}

else if(phpVer =~ "^(4\.4\.15)")
{
  if(version_is_less(version:phpVer, test_version:"4.4.15.7"))
  {
    fix = "4.4.15.7";
    VULN = TRUE;
  }
}

else if(phpVer =~ "^(4\.6)")
{
  if(version_is_less(version:phpVer, test_version:"4.6.3"))
  {
    fix = "4.6.3";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:phpVer, fixed_version:fix);
  security_message(port:phpPort, data:report);
  exit(0);
}
