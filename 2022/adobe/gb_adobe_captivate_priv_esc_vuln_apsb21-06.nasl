# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:captivate";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826531");
  script_version("2024-11-22T15:40:47+0000");
  script_cve_id("CVE-2021-21011");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-19 15:38:00 +0000 (Tue, 19 Jan 2021)");
  script_tag(name:"creation_date", value:"2022-09-16 12:30:45 +0530 (Fri, 16 Sep 2022)");
  ##Qod is reduced to 30, due to hotfix provided cannot be detected.
  script_tag(name:"qod", value:"30");
  script_name("Adobe Captivate Privilege Escalation Vulnerability (APSB21-06) - Windows");

  script_tag(name:"summary", value:"Adobe Captivate is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an uncontrolled search path
  element.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  escalate privileges on the target system.");

  script_tag(name:"affected", value:"Adobe Captivate 11.5.1.499 and earlier versions.");

  script_tag(name:"solution", value:"Update to version 11.5.1.499 and apple the hotfix.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/captivate/apsb21-06.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_adobe_captivate_detect.nasl");
  script_mandatory_keys("Adobe/Captivate/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"11.5.1.499")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Update to version 11.5.1.499 and apply the hotfix");
  security_message(data:report);
  exit(0);
}

exit(99);
