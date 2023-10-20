# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2023.40");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-4863");
  script_tag(name:"creation_date", value:"2023-09-13 07:36:11 +0000 (Wed, 13 Sep 2023)");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-18 17:48:00 +0000 (Mon, 18 Sep 2023)");

  script_name("Mozilla Firefox Security Advisory (MFSA2023-40) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2023-40");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-40/");
  script_xref(name:"URL", value:"https://bugs.chromium.org/p/chromium/issues/detail?id=1479274");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1852649");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-4863");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-4863: Heap buffer overflow in libwebp
Opening a malicious WebP image could lead to a heap buffer overflow in the content process. We are aware of this issue being exploited in other products in the wild. Note: This advisory was previously also tracked as CVE-2023-5129.");

  script_tag(name:"affected", value:"Firefox version(s) below 117.0.1.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the reference(s) for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "117.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "117.0.1", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
