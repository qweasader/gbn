# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810838");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-5400", "CVE-2017-5401", "CVE-2017-5402", "CVE-2017-5403",
                "CVE-2017-5404", "CVE-2017-5406", "CVE-2017-5407", "CVE-2017-5410",
                "CVE-2017-5398", "CVE-2017-5408", "CVE-2017-5412", "CVE-2017-5413",
                "CVE-2017-5414", "CVE-2017-5416", "CVE-2017-5425", "CVE-2017-5399",
                "CVE-2017-5418", "CVE-2017-5419", "CVE-2017-5405", "CVE-2017-5421",
                "CVE-2017-5422");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-01 12:05:00 +0000 (Wed, 01 Aug 2018)");
  script_tag(name:"creation_date", value:"2017-04-11 10:24:42 +0530 (Tue, 11 Apr 2017)");
  script_name("Mozilla Thunderbird Security Advisories (MFSA2017-09, MFSA2017-09) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - asm.js JIT-spray bypass of ASLR and DEP.

  - Memory Corruption when handling ErrorResult.

  - Use-after-free working with events in FontFace objects.

  - Use-after-free using addRange to add range to an incorrect root object.

  - Use-after-free working with ranges in selections.

  - Segmentation fault in Skia with canvas operations.

  - Pixel and history stealing via floating-point timing side channel with SVG filters.

  - Memory corruption during JavaScript garbage collection incremental sweeping.

  - Use-after-free in Buffer Storage in libGLES.

  - Cross-origin reading of video captions in violation of CORS.

  - Buffer overflow read in SVG filters.

  - Segmentation fault during bidirectional operations.

  - File picker can choose incorrect default directory.

  - Null dereference crash in HttpChannel.

  - Overly permissive Gecko Media Plugin sandbox regular expression access.

  - Gecko Media Plugin sandbox is not started if seccomp-bpf filter is running.

  - Out of bounds read when parsing HTTP digest authorization responses.

  - Repeated authentication prompts lead to DOS attack.

  - FTP response codes can cause use of uninitialized values for ports.

  - Print preview spoofing.

  - DOS attack by using view-source: protocol repeatedly in one hyperlink.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to execute arbitrary code, to delete arbitrary files
  by leveraging certain local file execution, to obtain sensitive information,
  and to cause a denial of service.");

  script_tag(name:"affected", value:"Mozilla Thunderbird versions before 52.0.");

  script_tag(name:"solution", value:"Update to version 52.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-09");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96654");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96677");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96664");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96691");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96692");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96693");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96694");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96651");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"52.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"52.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
