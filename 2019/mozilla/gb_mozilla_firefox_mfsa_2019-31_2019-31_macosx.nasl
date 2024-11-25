# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815474");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2019-11754");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-09-19 15:33:23 +0530 (Thu, 19 Sep 2019)");
  script_name("Mozilla Firefox Security Advisories (MFSA2019-31, MFSA2019-31) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to hijacking vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to not giving any user
  notification when the pointer lock is enabled by a website though
  'requestPointerLock' function.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  hijack the mouse pointer and confuse users.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  69.0.1 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 69.0.1
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-31");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"69.0.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"69.0.1", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
