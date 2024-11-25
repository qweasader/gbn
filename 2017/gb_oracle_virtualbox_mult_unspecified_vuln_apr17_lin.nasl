# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811010");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2017-3561", "CVE-2017-3563", "CVE-2017-3576", "CVE-2017-3558",
                "CVE-2017-3587", "CVE-2017-3559", "CVE-2017-3575", "CVE-2017-3513");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-04-25 15:14:16 +0530 (Tue, 25 Apr 2017)");
  script_name("Oracle Virtualbox Multiple Unspecified Vulnerabilities - 01 (Apr 2017) - Linux");

  script_tag(name:"summary", value:"Oracle VM VirtualBox is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors in the 'Core' and 'Shared Folder' sub-component of the
  application.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to have an impact on availability, confidentiality and integrity.");

  script_tag(name:"affected", value:"VirtualBox versions prior to 5.0.38
  and prior to 5.1.20 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox 5.0.38 or 5.1.20 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97730");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97732");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97759");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97744");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97750");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97739");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97755");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97736");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!virtualVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(virtualVer =~ "^(5\.0)")
{
  if(version_is_less(version:virtualVer, test_version:"5.0.38"))
  {
    fix = "5.0.38";
    VULN = TRUE;
  }
}

else if(virtualVer =~ "^(5\.1)")
{
  if(version_is_less(version:virtualVer, test_version:"5.1.20"))
  {
    fix = "5.1.20";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver( installed_version:virtualVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
