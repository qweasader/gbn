# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803119");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2012-5130", "CVE-2012-5132", "CVE-2012-5133", "CVE-2012-5134",
                "CVE-2012-5135", "CVE-2012-5136");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-12-04 11:44:20 +0530 (Tue, 04 Dec 2012)");
  script_name("Google Chrome Multiple Vulnerabilities-01 Dec2012 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51437/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56684");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/11/stable-channel-update.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 23.0.1271.91 on Linux");
  script_tag(name:"insight", value:"- An out-of-bounds read error exists in Skia.

  - A use-after-free error exists in SVG filters and in within printing.

  - Heap-based buffer underflow in the xmlParseAttValueComplex function in
    parser.c in libxmlier, allows remote attackers to cause a denial of service
    or possibly execute arbitrary code via crafted entities in an XML document.

  - A bad cast error exists within input element handling.

  - Browser crash with chunked encoding.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 23.0.1271.91 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"23.0.1271.91")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"23.0.1271.91");
  security_message(port:0, data:report);
}
