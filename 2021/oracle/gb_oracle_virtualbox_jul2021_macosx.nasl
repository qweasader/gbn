# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818166");
  script_version("2024-02-23T14:36:45+0000");
  script_cve_id("CVE-2021-2409", "CVE-2021-2454", "CVE-2021-2443", "CVE-2021-2442");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-23 14:36:45 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-23 13:30:00 +0000 (Fri, 23 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-28 15:58:03 +0530 (Wed, 28 Jul 2021)");
  script_name("Oracle VirtualBox Security Update (cpujul2021) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing a security update
  according to Oracle.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple errors
  in 'Core' component.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  have an impact on confidentiality, integrity and availability.");

  script_tag(name:"affected", value:"VirtualBox versions prior to 6.1.24 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox version 6.1.24 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2021.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_oracle_virtualbox_detect_macosx.nasl");
  script_mandatory_keys("Oracle/VirtualBox/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if(version_is_less(version:version, test_version:"6.1.24")) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.1.24", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
