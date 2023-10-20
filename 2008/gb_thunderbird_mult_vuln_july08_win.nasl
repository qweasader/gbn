# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800012");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-10-06 13:07:14 +0200 (Mon, 06 Oct 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2802", "CVE-2008-2803",
                "CVE-2008-2807", "CVE-2008-2809", "CVE-2008-2811");
  script_xref(name:"CB-A", value:"08-0109");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities July-08 (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");

  script_tag(name:"insight", value:"The issues are due to:

  - multiple errors in the layout and JavaScript engines that can corrupt
    memory.

  - error while handling unprivileged XUL documents that can be exploited to load
    chrome scripts from a fastload file via <script> elements.

  - error in mozIJSSubScriptLoader.LoadScript function that can bypass
    XPCNativeWrappers.

  - error in block re-flow process, which can potentially lead to crash.

  - errors in the implementation of the Javascript same origin policy

  - error in processing of Alt Names provided by peer.

  - error in processing of windows URL shortcuts.");

  script_tag(name:"solution", value:"Upgrade to Thunderbird version 2.0.0.16.");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"affected", value:"Thunderbird version prior to 2.0.0.16 on Windows.");

  script_tag(name:"impact", value:"Successful exploitation could result in remote arbitrary code execution,
  spoofing attacks, sensitive information disclosure, and can crash the browser.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-21.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30038");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-24.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-25.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-29.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-31.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-33.html");

  exit(0);
}

if(egrep(pattern:"^([01]\..*|2\.0(\.0\.(0?[0-9]|1[0-5]))?)$",
         string:get_kb_item("Thunderbird/Win/Ver"))){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
