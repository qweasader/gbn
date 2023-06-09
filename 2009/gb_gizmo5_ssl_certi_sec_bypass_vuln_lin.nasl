# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800833");
  script_version("2023-05-11T09:09:33+0000");
  script_tag(name:"last_modification", value:"2023-05-11 09:09:33 +0000 (Thu, 11 May 2023)");
  script_tag(name:"creation_date", value:"2009-07-15 13:05:34 +0200 (Wed, 15 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2381");
  script_name("Gizmo5 <= 3.1.0.79 SSL Certificate Validation Security Bypass Vulnerability - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35628");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35508");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51399");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/504572/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_gizmo5_detect_lin.nasl");
  script_mandatory_keys("Gizmo5/Linux/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  sensitive information that could be used to launch further attacks against the victim's system.");

  script_tag(name:"affected", value:"Gizmo5 version 3.1.0.79 and prior on Linux.");

  script_tag(name:"insight", value:"Error exists due to improper verification of SSL certificates
  which can be exploited by using man-in-the-middle techniques to spoof SSL
  certificates and redirect a user to a malicious Web site that would appear to be trusted.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Gizmo5 is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("version_func.inc");

gizmoVer = get_kb_item("Gizmo5/Linux/Ver");
if(!gizmoVer){
  exit(0);
}

if(version_is_less_equal(version:gizmoVer, test_version:"3.1.0.79")){
  security_message(port:0);
}