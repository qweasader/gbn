# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871395");
  script_version("2023-07-12T05:05:04+0000");
  script_cve_id("CVE-2012-5667", "CVE-2015-1345");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-07-23 06:24:50 +0200 (Thu, 23 Jul 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for grep RHSA-2015:1447-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'grep'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The grep utility searches through textual input for lines that contain a
match to a specified pattern and then prints the matching lines. The GNU
grep utilities include grep, egrep, and fgrep.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way grep parsed large lines of data. An attacker able to trick
a user into running grep on a specially crafted data file could use this
flaw to crash grep or, potentially, execute arbitrary code with the
privileges of the user running grep. (CVE-2012-5667)

A heap-based buffer overflow flaw was found in the way grep processed
certain pattern and text combinations. An attacker able to trick a user
into running grep on specially crafted input could use this flaw to crash
grep or, potentially, read from uninitialized memory. (CVE-2015-1345)

The grep packages have been upgraded to upstream version 2.20, which
provides a number of bug fixes and enhancements over the previous version.
Notably, the speed of various operations has been improved significantly.
Now, the recursive grep utility uses the fts function of the gnulib library
for directory traversal, so that it can handle much larger directories
without reporting the 'File name too long' error message, and it can
operate faster when dealing with large directory hierarchies. (BZ#982215,
BZ#1064668, BZ#1126757, BZ#1167766, BZ#1171806)

This update also fixes the following bugs:

  * Prior to this update, the \w and \W symbols were inconsistently matched
to the [:alnum:] character class. Consequently, regular expressions that
used \w and \W in some cases had incorrect results. An upstream patch which
fixes the matching problem has been applied, and \w is now matched to the
[_[:alnum:]] character and \W to the [^_[:alnum:]] character consistently.
(BZ#799863)

  * Previously, the '--fixed-regexp' command-line option was not included in
the grep(1) manual page. Consequently, the manual page was inconsistent
with the built-in help of the grep utility. To fix this bug, grep(1) has
been updated to include a note informing the user that '--fixed-regexp' is
an obsolete option. Now, the built-in help and manual page are consistent
regarding the '--fixed-regexp' option. (BZ#1103270)

  * Previously, the Perl Compatible Regular Expression (PCRE) library did not
work correctly when matching non-UTF-8 text in UTF-8 mode. Consequently, an
error message about invalid UTF-8 byte sequence characters was returned.
To fix this bug, patches from upstream have been applied to the PCRE
l ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"grep on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:1447-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-July/msg00033.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"grep", rpm:"grep~2.20~3.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"grep-debuginfo", rpm:"grep-debuginfo~2.20~3.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
