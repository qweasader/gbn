# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809806");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-5296", "CVE-2016-5293", "CVE-2016-5294", "CVE-2016-5297",
                "CVE-2016-9064", "CVE-2016-9066", "CVE-2016-5291", "CVE-2016-9074",
                "CVE-2016-5290");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-30 12:53:00 +0000 (Mon, 30 Jul 2018)");
  script_tag(name:"creation_date", value:"2016-11-16 13:10:33 +0530 (Wed, 16 Nov 2016)");
  script_name("Mozilla Firefox ESR Security Updates (mfsa_2016-89_2016-90)-Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Heap-buffer-overflow WRITE in rasterize_edges_1.

  - Write to arbitrary file with Mozilla Updater and Maintenance Service using
    updater.log hardlink.

  - Arbitrary target directory for result files of update process.

  - Incorrect argument length checking in JavaScript.

  - Add-ons update must verify IDs match between current and new versions.

  - Integer overflow leading to a buffer overflow in nsScriptLoadHandler.

  - Same-origin policy violation using local HTML file and saved shortcut file.

  - Insufficient timing side-channel resistance in divSpoiler.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to execute arbitrary code, to delete
  arbitrary files by leveraging certain local file execution, to obtain sensitive
  information, and to cause a denial of service.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  45.5 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 45.5
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-90/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94336");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94337");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94342");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94339");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"45.5"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"45.5");
  security_message(data:report);
  exit(0);
}
