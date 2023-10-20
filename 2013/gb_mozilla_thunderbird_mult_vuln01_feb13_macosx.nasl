# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803425");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-0784", "CVE-2013-0783", "CVE-2013-0782", "CVE-2013-0781",
                "CVE-2013-0780", "CVE-2013-0779", "CVE-2013-0778", "CVE-2013-0777",
                "CVE-2013-0765", "CVE-2013-0772", "CVE-2013-0773", "CVE-2013-0774",
                "CVE-2013-0775", "CVE-2013-0776");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-02-21 19:36:53 +0530 (Thu, 21 Feb 2013)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities -01 Feb13 (Mac OS X)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52249");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58034");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58036");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58037");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58038");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58040");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58041");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58042");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58043");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58044");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58047");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58048");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58049");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58050");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58051");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52280");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=827070");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/cve/CVE-2013-0784");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-28.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  memory corruption, bypass certain security restrictions and compromise a user's system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 17.0.3 on Mac OS X");

  script_tag(name:"insight", value:"- Error when handling a WebIDL object

  - Error in displaying the content of a 407 response of a proxy

  - Unspecified errors in 'nsSaveAsCharset::DoCharsetConversion()' function,
    Chrome Object Wrappers (COW) and in System Only Wrappers (SOW).

  - Use-after-free error in the below functions

    'nsDisplayBoxShadowOuter::Paint()'

    'nsPrintEngine::CommonPrint()'

    'nsOverflowContinuationTracker::Finish()'

    'nsImageLoadingContent::OnStopContainer()'

  - Out-of-bound read error in below functions

    'ClusterIterator::NextCluster()'

    'nsCodingStateMachine::NextState()'

    'mozilla::image::RasterImage::DrawFrameTo()', when rendering GIF images.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 17.0.3 or later.");
  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Thunderbird/MacOSX/Version");
if(vers) {
  if(version_is_less(version:vers, test_version:"17.0.3"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"17.0.3");
    security_message(port: 0, data: report);
    exit(0);
  }
}
