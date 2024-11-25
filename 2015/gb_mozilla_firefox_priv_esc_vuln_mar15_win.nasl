# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805514");
  script_version("2024-11-22T15:40:47+0000");
  script_cve_id("CVE-2015-0818");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2015-03-27 13:32:25 +0530 (Fri, 27 Mar 2015)");
  script_name("Mozilla Firefox SVG Navigation Privilege Escalation Vulnerability (Mar 2015) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in
  docshell/base/nsDocShell.cpp within the SVG format content navigation
  functionality.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain elevated privileges and execute arbitrary scripts with the
  elevated privileges.");

  script_tag(name:"affected", value:"Mozilla Firefox before version 36.0.4 on
  Windows");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 36.0.4
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1031959");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-28");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:ffVer, test_version:"36.0.4"))
{
  report = 'Installed version: ' + ffVer + '\n' +
           'Fixed version:     36.0.4\n';
  security_message(data:report);
  exit(0);
}
