# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126142");
  script_version("2023-09-19T05:06:03+0000");
  script_tag(name:"last_modification", value:"2023-09-19 05:06:03 +0000 (Tue, 19 Sep 2023)");
  script_tag(name:"creation_date", value:"2022-09-16 08:58:43 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"2.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2022-39194");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("MediaWiki 1.37.x - 1.38.x DoS Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Denial of Service");

  script_tag(name:"summary", value:"MediaWiki is prone to a denial of service (DoS)
  vulnerability.

  This VT has been deprecated since the vulnerability is in an extension and not in MediaWiki itself.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Growth's Community configuration makes it possible for rogue
  admin to take down a site.");

  script_tag(name:"affected", value:"MediaWiki version 1.37.x through 1.38.x.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/mediawiki-announce@lists.wikimedia.org/message/SJLXUZZUHQDSSSKIOXMMV7Y4YXPAXZXI");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
