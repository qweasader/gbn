# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810809");
  script_version("2023-10-13T16:09:03+0000");
  script_cve_id("CVE-2017-2997", "CVE-2017-2998", "CVE-2017-2999", "CVE-2017-3000",
                "CVE-2017-3001", "CVE-2017-3002", "CVE-2017-3003");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-24 14:31:00 +0000 (Tue, 24 Jan 2023)");
  script_tag(name:"creation_date", value:"2017-03-15 08:18:23 +0530 (Wed, 15 Mar 2017)");
  script_name("Adobe Flash Player Security Updates(apsb17-07) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A buffer overflow vulnerability.

  - The memory corruption vulnerabilities.

  - A random number generator vulnerability used for constant blinding.

  - The use-after-free vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to execute arbitrary code on
  the target user's system and that could potentially allow an attacker to
  take control of the affected system.");

  script_tag(name:"affected", value:"Adobe Flash Player versions before
  25.0.0.127 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  25.0.0.127, or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb17-07.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96860");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96866");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96862");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96861");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"25.0.0.127"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"25.0.0.127");
  security_message(data:report);
  exit(0);
}

