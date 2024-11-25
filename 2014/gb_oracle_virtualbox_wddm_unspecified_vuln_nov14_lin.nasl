# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804950");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-6540");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-11-03 11:58:04 +0530 (Mon, 03 Nov 2014)");
  script_name("Oracle Virtualbox WDDM Unspecified Vulnerability (Nov 2014) - Linux");

  script_tag(name:"summary", value:"Oracle VM VirtualBox is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is  due to an error related to
  Graphics driver (WDDM) for Windows Guests subcomponent.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  cause denial of service attack.");

  script_tag(name:"affected", value:"VirtualBox version 4.1.x before 4.1.34, 4.2.x
  before 4.2.26, and 4.3.x before 4.3.14 on Linux");

  script_tag(name:"solution", value:"Upgrade to Oracle VM VirtualBox version
  4.1.34 or 4.2.26 or 4.3.14 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/61582/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70493");
  script_xref(name:"URL", value:"http://cve.circl.lu/cve/CVE-2014-6540");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!virtualVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(virtualVer =~ "^(4\.(1|2|3))")
{
  if(version_in_range(version:virtualVer, test_version:"4.2.0", test_version2:"4.2.25")||
     version_in_range(version:virtualVer, test_version:"4.3.0", test_version2:"4.3.13") ||
     version_in_range(version:virtualVer, test_version:"4.1.0", test_version2:"4.1.33"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
