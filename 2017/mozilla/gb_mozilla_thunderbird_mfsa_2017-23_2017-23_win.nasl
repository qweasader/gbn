# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811940");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-7793", "CVE-2017-7818", "CVE-2017-7819", "CVE-2017-7824",
                "CVE-2017-7805", "CVE-2017-7814", "CVE-2017-7823", "CVE-2017-7810");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-01 12:05:00 +0000 (Wed, 01 Aug 2018)");
  script_tag(name:"creation_date", value:"2017-10-12 11:10:23 +0530 (Thu, 12 Oct 2017)");
  script_name("Mozilla Thunderbird Security Updates (mfsa_2017-23_2017-23)-Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Use-after-free with Fetch API.

  - Use-after-free during ARIA array manipulation.

  - Use-after-free while resizing images in design mode.

  - Buffer overflow when drawing and validating elements with ANGLE.

  - Use-after-free in TLS 1.2 generating handshake hashes.

  - Blob and data URLs bypass phishing and malware protection warnings.

  - OS X fonts render some Tibetan and Arabic unicode characters as spaces.

  - CSP sandbox directive did not create a unique origin.

  - Memory safety bugs fixed inThunderbird 52.4");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to gain access to potentially sensitive information,
  execute arbitrary code and conduct a denial-of-service condition.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 52.4 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Thunderbird version 52.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-23/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101055");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101053");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101059");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101054");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"52.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"52.4");
  security_message(data:report);
  exit(0);
}

exit(99);
