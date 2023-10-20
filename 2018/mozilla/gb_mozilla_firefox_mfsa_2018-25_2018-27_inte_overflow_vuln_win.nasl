# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814418");
  script_version("2023-07-20T05:05:18+0000");
  script_cve_id("CVE-2018-12393");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-10-24 16:40:00 +0530 (Wed, 24 Oct 2018)");
  script_name("Mozilla Firefox Security Update (mfsa_2018-25_2018-27) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to an integer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Check if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an integer overflow during
  the conversion of scripts to an internal UTF-16 representation.");

  script_tag(name:"impact", value:"Successful exploitation will lead to a
  possible out-of-bounds write.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 63 on Windows.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox version 63
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-26");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_exclude_keys("Firefox64/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"63")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"63", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);