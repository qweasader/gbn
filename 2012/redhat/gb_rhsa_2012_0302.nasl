# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-February/msg00058.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870561");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-02-21 18:57:05 +0530 (Tue, 21 Feb 2012)");
  script_cve_id("CVE-2011-2896");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_xref(name:"RHSA", value:"2012:0302-03");
  script_name("RedHat Update for cups RHSA-2012:0302-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"cups on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The Common UNIX Printing System (CUPS) provides a portable printing layer
  for Linux, UNIX, and similar operating systems.

  A heap-based buffer overflow flaw was found in the Lempel-Ziv-Welch (LZW)
  decompression algorithm implementation used by the CUPS GIF image format
  reader. An attacker could create a malicious GIF image file that, when
  printed, could possibly cause CUPS to crash or, potentially, execute
  arbitrary code with the privileges of the 'lp' user. (CVE-2011-2896)

  This update also fixes the following bugs:

  * Prior to this update, the 'Show Completed Jobs, ' 'Show All Jobs, ' and
  'Show Active Jobs' buttons returned results globally across all printers
  and not the results for the specified printer. With this update, jobs from
  only the selected printer are shown. (BZ#625900)

  * Prior to this update, the code of the serial backend contained a wrong
  condition. As a consequence, print jobs on the raw print queue could not be
  canceled. This update modifies the condition in the serial backend code.
  Now, the user can cancel these print jobs. (BZ#625955)

  * Prior to this update, the textonly filter did not work if used as a pipe,
  for example when the command line did not specify the filename and the
  number of copies was always 1. This update modifies the condition in the
  textonly filter. Now, the data are sent to the printer regardless of the
  number of copies specified. (BZ#660518)

  * Prior to this update, the file descriptor count increased until it ran
  out of resources when the cups daemon was running with enabled
  Security-Enhanced Linux (SELinux) features. With this update, all resources
  are allocated only once. (BZ#668009)

  * Prior to this update, CUPS incorrectly handled the en_US.ASCII value for
  the LANG environment variable. As a consequence, the lpadmin, lpstat, and
  lpinfo binaries failed to write to standard output if using LANG with the
  value. This update fixes the handling of the en_US.ASCII value and the
  binaries now write to standard output properly. (BZ#759081)

  All users of cups are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. After installing this
  update, the cupsd daemon will be restarted automatically.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.3.7~30.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~1.3.7~30.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.3.7~30.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.3.7~30.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-lpd", rpm:"cups-lpd~1.3.7~30.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
