# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-April/msg00019.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870713");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-09 10:51:55 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-3062", "CVE-2012-0467", "CVE-2012-0468", "CVE-2012-0469",
                "CVE-2012-0470", "CVE-2012-0471", "CVE-2012-0472", "CVE-2012-0473",
                "CVE-2012-0474", "CVE-2012-0477", "CVE-2012-0478", "CVE-2012-0479");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"RHSA", value:"2012:0516-01");
  script_name("RedHat Update for thunderbird RHSA-2012:0516-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"thunderbird on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

  A flaw was found in Sanitiser for OpenType (OTS), used by Thunderbird to
  help prevent potential exploits in malformed OpenType fonts. Malicious
  content could cause Thunderbird to crash or, under certain conditions,
  possibly execute arbitrary code with the privileges of the user running
  Thunderbird. (CVE-2011-3062)

  Malicious content could cause Thunderbird to crash or, potentially, execute
  arbitrary code with the privileges of the user running Thunderbird.
  (CVE-2012-0467, CVE-2012-0468, CVE-2012-0469)

  Content containing a malicious Scalable Vector Graphics (SVG) image file
  could cause Thunderbird to crash or, potentially, execute arbitrary code
  with the privileges of the user running Thunderbird. (CVE-2012-0470)

  A flaw was found in the way Thunderbird used its embedded Cairo library to
  render certain fonts. Malicious content could cause Thunderbird to crash
  or, under certain conditions, possibly execute arbitrary code with the
  privileges of the user running Thunderbird. (CVE-2012-0472)

  A flaw was found in the way Thunderbird rendered certain images using
  WebGL. Malicious content could cause Thunderbird to crash or, under certain
  conditions, possibly execute arbitrary code with the privileges of the user
  running Thunderbird. (CVE-2012-0478)

  A cross-site scripting (XSS) flaw was found in the way Thunderbird handled
  certain multibyte character sets. Malicious content could cause Thunderbird
  to run JavaScript code with the permissions of different content.
  (CVE-2012-0471)

  A flaw was found in the way Thunderbird rendered certain graphics using
  WebGL. Malicious content could cause Thunderbird to crash. (CVE-2012-0473)

  A flaw in the built-in feed reader in Thunderbird allowed the Website field
  to display the address of different content than the content the user was
  visiting. An attacker could use this flaw to conceal a malicious URL,
  possibly tricking a user into believing they are viewing a trusted site, or
  allowing scripts to be loaded from the attacker's site, possibly leading to
  cross-site scripting (XSS) attacks. (CVE-2012-0474)

  A flaw was found in the way Thunderbird decoded the ISO-2022-KR and
  ISO-2022-CN character sets. Malicious content could cause Thunderbird
  to run JavaScript code with the permissions of different content.
  (CVE-2012-0477)

  A flaw was found in the way the built-in feed reader in Thunderbird handled
  RSS and Atom feeds. Invalid RSS o ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~10.0.4~1.el6_2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"thunderbird-debuginfo", rpm:"thunderbird-debuginfo~10.0.4~1.el6_2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
