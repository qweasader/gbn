# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801122");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3546");
  script_name("GD Graphics Library '_gdGetColors()' Buffer Overflow Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to potentially
  compromise a vulnerable system.");

  script_tag(name:"affected", value:"GD Graphics Library version 2.x.");

  script_tag(name:"insight", value:"The flaw is due to error in '_gdGetColors' function in gd_gd.c
  which fails to check certain colorsTotal structure member, whicn can be exploited
  to cause buffer overflow or buffer over-read attacks via a crafted GD file.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"GD Graphics Library is prone to a buffer overflow vulnerability.

  This VT may create FP and LSC's are taking care of it.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37069/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36712");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2929");
  script_xref(name:"URL", value:"http://marc.info/?l=oss-security&m=125562113503923&w=2");
  exit(0);
}

exit(66); ## This VT is deprecated as it may create FP.