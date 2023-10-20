# SPDX-FileCopyrightText: 2002 Michael Scheidell
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10835");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0876");
  script_name("Unchecked Buffer in XP upnp");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Michael Scheidell");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"Unchecked Buffer in Universal Plug and Play Can
  Lead to System Compromise for Windows XP (Q315000)");

  script_tag(name:"impact", value:"By sending a specially-malformed NOTIFY directive,
  it would be possible for an attacker to cause code to run in the context of the UPnP
  service, which runs with system privileges on Windows XP.

  The UPnP implementations do not adequately regulate how it performs this operation,
  and this gives rise to two different denial-of-service scenarios. (CVE-2001-0877)");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2001/ms01-059");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3723");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_sp(xp:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q315000") > 0 )
  security_message(port:0);
