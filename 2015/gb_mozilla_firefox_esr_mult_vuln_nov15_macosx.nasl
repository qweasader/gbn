# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806553");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-7200", "CVE-2015-7199", "CVE-2015-7198", "CVE-2015-7197",
                "CVE-2015-7196", "CVE-2015-7194", "CVE-2015-7193", "CVE-2015-7189",
                "CVE-2015-7188", "CVE-2015-4513", "CVE-2015-7183", "CVE-2015-7182",
                "CVE-2015-7181");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-11-09 16:15:18 +0530 (Mon, 09 Nov 2015)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities - Nov15 (Mac OS X)");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are exists due to:

  - Lack of status checking in CryptoKey interface implementation.

  - Lack of status checking in 'AddWeightedPathSegLists' and
   'SVGPathSegListSMILType::Interpolate' functions.

  - Buffer overflow in the 'rx::TextureStorage11' class in ANGLE graphics
    library.

  - An error in 'web worker' when creating WebSockets.

  - Java plugin can deallocate a JavaScript wrapper when it is still in use,
    which leads to a JavaScript garbage collection crash.

  - Buffer underflow in 'libjar' triggered through a maliciously crafted ZIP
    format file.

  - An error in implementation of CORS cross-origin request algorithm.

  - Buffer overflow in the 'JPEGEncoder' function during script interactions with
    a canvas element.

  - Trailing whitespaces are evaluated differently when parsing IP addresses
    instead of alphanumeric hostnames.

  - Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox.

  - Multiple memory corruption issues in NSS and NSPR.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service or possibly execute arbitrary code,
  bypass security restrictions, to obtain sensitive information and some
  unspecified impacts.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version 38.x
  before 38.4 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version
  38.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2015/mfsa2015-131.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77415");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77416");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2015/mfsa2015-133.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(ffVer =~ "^38\.")
{
  if(version_is_less(version:ffVer, test_version:"38.4"))
  {
    report = 'Installed version: ' + ffVer + '\n' +
             'Fixed version:     ' + "38.4" + '\n';
    security_message(data:report);
    exit(0);
  }
}
