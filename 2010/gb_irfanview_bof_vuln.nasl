# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801338");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_cve_id("CVE-2010-1510", "CVE-2010-1509");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("IrfanView Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39036");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-41");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_irfanview_detect.nasl");
  script_mandatory_keys("IrfanView/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to allow execution of arbitrary
  code or to compromise a user's system.");
  script_tag(name:"affected", value:"IrfanView version prior to 4.27");
  script_tag(name:"solution", value:"Upgrade to version 4.27 or later.");
  script_tag(name:"summary", value:"IrfanView is prone to buffer overflow vulnerabilities.");
  script_tag(name:"insight", value:"The flaws are due to:

  - A sign extension error when parsing certain 'PSD' images

  - A boundary error when processing certain 'RLE' compressed 'PSD' images.

   These can be exploited to cause a heap-based buffer overflow by tricking a
   user into opening a specially crafted PSD file.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

irViewVer = get_kb_item("IrfanView/Ver");
if(!irViewVer){
  exit(0);
}

if(version_is_less(version:irViewVer, test_version:"4.27")){
  report = report_fixed_ver(installed_version:irViewVer, fixed_version:"4.27");
  security_message(port: 0, data: report);
}
