# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801287");
  script_version("2023-07-28T16:09:07+0000");
  script_cve_id("CVE-2006-2370", "CVE-2006-2371", "CVE-2007-1748", "CVE-2008-4250", "CVE-2009-3103");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-09-23 08:22:30 +0200 (Thu, 23 Sep 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Nmap NSE: SMB Check Vulnerabilities");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Nmap NSE");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securityadvisories/2009/975497");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-029");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2006/ms06-025");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067");

  script_tag(name:"summary", value:"This script attempts to check the following vulnerabilities:

  - MS08-067, a Windows RPC vulnerability

  - Conficker, an infection by the Conficker worm

  - Unnamed regsvc DoS

  - SMBv2 exploit (CVE-2009-3103)

  This is a wrapper on the Nmap Security Scanner's smb-check-vulns.nse.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
