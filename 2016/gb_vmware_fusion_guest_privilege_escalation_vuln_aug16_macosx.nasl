# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:fusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809004");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2015-6933");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 18:22:00 +0000 (Wed, 07 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-08-19 11:02:52 +0530 (Fri, 19 Aug 2016)");
  script_name("VMware Fusion Guest Privilege Escalation Vulnerability Aug16 (Mac OS X)");

  script_tag(name:"summary", value:"VMware Fusion is prone to an important guest privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a kernel memory
  corruption vulnerability is present in the VMware Tools 'Shared Folders'
  (HGFS) feature running on Microsoft Windows.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  authenticated attacker on a guest operating system to gain elevated
  privileges on the guest operating system.");

  script_tag(name:"affected", value:"VMware Fusion 7.x before 7.1.2 on
  Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to VMware Fusion version
  7.1.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0001.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/79958");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=42939");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_vmware_fusion_detect_macosx.nasl");
  script_mandatory_keys("VMware/Fusion/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vmwareVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(vmwareVer =~ "^7\.")
{
  if(version_is_less(version:vmwareVer, test_version:"7.1.2"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"7.1.2");
    security_message(data:report);
    exit(0);
  }
}
