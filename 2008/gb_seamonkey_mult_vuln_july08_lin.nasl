# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800022");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-10-07 14:21:23 +0200 (Tue, 07 Oct 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800", "CVE-2008-2801",
                "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2805", "CVE-2008-2806",
                "CVE-2008-2807", "CVE-2008-2808", "CVE-2008-2809", "CVE-2008-2810",
                "CVE-2008-2811");
  script_xref(name:"CB-A", value:"08-0109");
  script_name("Mozilla Seamonkey Multiple Vulnerabilities (Jul 2008) - Linux");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-21.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30038");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-22.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-23.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-24.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-25.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-27.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-28.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-29.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-30.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-31.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-32.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-33.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_lin.nasl");
  script_mandatory_keys("Seamonkey/Linux/Ver");

  script_tag(name:"impact", value:"Successful exploitation could result in remote arbitrary code execution,
  spoofing attacks, sensitive information disclosure, and JavaScript code
  can execute with the privileges of JAR's signer.");

  script_tag(name:"affected", value:"Seamonkey version prior to 1.1.10 on Linux.");

  script_tag(name:"insight", value:"Issues are due to:

  - multiple errors in the layout and JavaScript engines that can corrupt
    memory.

  - error while handling unprivileged XUL documents that can be exploited
    to load chrome scripts from a fastload file via <script> elements.

  - error in mozIJSSubScriptLoader.LoadScript function can bypass
    XPCNativeWrappers.

  - error in block re-flow process, which can potentially lead to crash.

  - error in processing file URLs contained within local directory listings.

  - errors in the implementation of the Javascript same origin policy

  - errors in the verification of signed JAR files.

  - improper implementation of file upload forms result in uploading specially
    crafted DOM Range and originalTarget elements.

  - error in Java LiveConnect implementation.

  - error in processing of Alt Names provided by peer.

  - error in processing of windows URL shortcuts.");

  script_tag(name:"solution", value:"Upgrade to Seamonkey version 1.1.10 or later.");

  script_tag(name:"summary", value:"Mozilla Seamonkey is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

ver = get_kb_item("Seamonkey/Linux/Ver");
if(!ver) exit(0);

if(egrep(pattern:"^(0\..*|1\.0(\..*)?|1\.1(\.0?[0-9])?)$", string:ver)){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
