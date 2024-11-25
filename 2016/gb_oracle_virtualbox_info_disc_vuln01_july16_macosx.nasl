# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808261");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2016-3612");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-07-21 12:24:33 +0530 (Thu, 21 Jul 2016)");
  script_name("Oracle Virtualbox Information Disclosure Vulnerability-01 (Jul 2016) - Mac OS X");

  script_tag(name:"summary", value:"Oracle VM VirtualBox is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to some unspecified
  error in an unknown function of the component SSL/TLS.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to have an impact on confidentiality.");

  script_tag(name:"affected", value:"VirtualBox versions prior to 5.0.22
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox version
  5.0.22 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91860");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_oracle_virtualbox_detect_macosx.nasl");
  script_mandatory_keys("Oracle/VirtualBox/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!virtualVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(virtualVer =~ "^5\.0\.")
{
  if(version_in_range(version:virtualVer, test_version:"5.0.0", test_version2:"5.0.21"))
  {
    report = report_fixed_ver(installed_version:virtualVer, fixed_version:"5.0.22");
    security_message(data:report);
    exit(0);
  }
}
