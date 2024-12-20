# SPDX-FileCopyrightText: 2009 Christian Eric Edjenguele
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Microsoft Security Bulletin MS03-018
# Cumulative Patch for Internet Information Service (811114)
# Redirection Cross Site Scripting CAN-2003-0223
# Server Side Include Web Pages Buffer Overrun CAN-2003-0224
# ASP Headers Denial of Service CAN-2003-0225
# Microsoft IIS 'SSINC.DLL' Include Buffer Overflow Vulnerability (MS03-018)
# WebDAV Denial of Service CAN-2003-0226
#
#
# Affected Software:
# Microsoft Internet Information Server 4.0
# Microsoft Internet Information Services 5.0
# Microsoft Internet Information Services 5.1
#
# Non Affected Software:
# Microsoft Internet Information Services 6.0
#
#
# Tested on:
#
# [Windows NT EN]
# - Windows NT SP3                            ->      39658520604f0e8aa50f9a81e98ea133 - Vulnerable
# - Windows NT SP6                            ->      39658520604f0e8aa50f9a81e98ea133 - Vulnerable
# - Windows NT SP6a + OP                  ->      39ff5076bc08e9135762e251d2694641 - Not Vulnerable
# - Windows NT SRP                            ->      39ff5076bc08e9135762e251d2694641 - Not Vulnerable
#
# [Windows 2000 EN]
# - Windows 2000 SP0                          ->      df65cc2183d93eec835e7369e7339080 - Vulnerable
# - Windows 2000 SP1                          ->      df65cc2183d93eec835e7369e7339080 - Vulnerable
# - Windows 2000 SP2                          ->      6ae807197693dc1d9eb364e1e590f69e - Vulnerable
# - Windows 2000 SP2 + ms03-018 Patch   ->      d17aefa456210ce25b6e315f50a5d8d0 - Not Vulnerable
# - Windows 2000 SP3                          ->      d17aefa456210ce25b6e315f50a5d8d0 - Vulnerable (Not implemented here)
# - Windows 2000 SP3 + ms03-018 Patch  ->      d17aefa456210ce25b6e315f50a5d8d0 - Not Vulnerable
# - Windows 2000 SP4                          ->      d17aefa456210ce25b6e315f50a5d8d0 - Not Vulnerable
# - Windows 2000 SRP                          ->      d17aefa456210ce25b6e315f50a5d8d0 - Not Vulnerable
# - Windows 2000 Windows Update           ->      d17aefa456210ce25b6e315f50a5d8d0 - Not Vulnerable
#
# [Windows 2000 IT]
# - Windows 2000 SP0                          ->      81f7ab909260148e04f662fc31e3c336 - Vulnerable
# - Windows 2000 SP1                          ->      81f7ab909260148e04f662fc31e3c336 - Vulnerable
# - Windows 2000 SP2                          ->      a723b2e8e9722b53d616ead1ef86e66b - Vulnerable
# - Windows 2000 SP2 + ms03-018           ->      389fe7f7596a41a13d6eb384e7f964d8 - Not Vulnerable
# - Windows 2000 SP3                          ->      389fe7f7596a41a13d6eb384e7f964d8 - Vulnerable (Not implemented here)
# - Windows 2000 SP3 + ms03-018           ->      389fe7f7596a41a13d6eb384e7f964d8 - Not Vulnerable
# - Windows 2000 SP4                          ->      389fe7f7596a41a13d6eb384e7f964d8 - Not Vulnerable
# - Windows 2000 SRP                          ->      389fe7f7596a41a13d6eb384e7f964d8 - Not Vulnerable
# - Windows 2000 Windows Update           ->      389fe7f7596a41a13d6eb384e7f964d8 - Not Vulnerable
#
# [Windows XP EN]
# - Windows XP SP1                            ->      979b3d197cf71be7f98c9d9e9acb61c0 - Vulnerable (Not implemented here)
# - Windows XP SP1 + ms03-018 Patch       ->      979b3d197cf71be7f98c9d9e9acb61c0 - Not Vulnerable (No differences in files with unpatched system)
# - Windows XP SP2                            ->      979b3d197cf71be7f98c9d9e9acb61c0 - Not Vulnerable (No differences in files with unpatched system)
#
# [Windows XP IT]
# - Windows XP SP0                            ->      a7945dc825ff65fe0c954fa41d763de0 - Vulnerable
# - Windows XP SP1                            ->      8e49af43858540be0754bd4f9074871e - Vulnerable (Not implemented here)
# - Windows XP SP1 + ms03-018 Patch       ->      8e49af43858540be0754bd4f9074871e - Not Vulnerable (No differences in files with unpatched system)
# - Windows XP SP2                            ->      8e49af43858540be0754bd4f9074871e - Not Vulnerable (No differences in files with unpatched system)
#
# [Windows 2003 EN]
# - Windows 2003 SP0                          ->      23d6b92bc7eb100fc1294e6b124b7e75 - Not Vulnerable
#
#
# End User Bulletin: An end user version of this bulletin is available at: http://www.microsoft.com/athome/security/update/bulletins/default.mspx

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101017");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2009-03-16 23:15:41 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2003-0223", "CVE-2003-0224", "CVE-2003-0225", "CVE-2003-0226");
  script_name("Microsoft IIS MS03-018 Security Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Windows : Microsoft Bulletins");

  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=1DBC1914-98E9-4DED-ADBF-E9B374A1F79D&displaylang=en");
  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=2F5D9852-4ADD-44F8-8715-AC3D7D7D94BF&displaylang=en");
  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=77CFE3EF-C5C5-401C-BC12-9F08154A5007&displaylang=en");
  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=86F4407E-B9BF-4490-9421-008407578D11&displaylang=en");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/241211");

  script_tag(name:"solution", value:"Microsoft has released a patch to correct these issues

  There is a dependency associated with this patch - it requires the patch from Microsoft Security Bulletin MS02-050 to be installed.
  If this patch is installed and MS02-050 is not present, client side certificates will be rejected.
  This functionality can be restored by installing the MS02-050 patch.");

  script_tag(name:"summary", value:"A Cross-Site Scripting(XSS)vulnerability affecting IIS 4.0, 5.0 and 5.1 involving the error message that's returned to advise that a
  requested URL has been redirected. An attacker who was able to lure a user into clicking a link on his or her web site could relay a request containing script to a
  third-party web site running IIS, thereby causing the third-party site's response (still including the script) to be sent to the user.
  The script would then render using the security settings of the third-party site rather than the attacker's.

  A buffer overrun that results because IIS 5.0 does not correctly validate requests for certain types of web pages known as server side includes.

  A denial of service vulnerability that results because of a flaw in the way IIS 4.0 and 5.0 allocate memory requests when constructing
  headers to be returned to a web client.

  A denial of service vulnerability that results because IIS 5.0 and 5.1 do not correctly handle an error condition when
  an overly long WebDAV request is passed to them. As a result an attacker could cause IIS to fail.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

# This VT is broken in many ways, especially as it is using a md5 hash
# on a response with dynamic data. This will never work against a live system...
exit(66);
