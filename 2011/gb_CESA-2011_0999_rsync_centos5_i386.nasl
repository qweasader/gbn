# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-September/017961.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881002");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2011:0999");
  script_cve_id("CVE-2007-6200");
  script_name("CentOS Update for rsync CESA-2011:0999 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rsync'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"rsync on CentOS 5");
  script_tag(name:"insight", value:"rsync is a program for synchronizing files over a network.

  A flaw was found in the way the rsync daemon handled the 'filter',
  'exclude', and 'exclude from' options, used for hiding files and preventing
  access to them from rsync clients. A remote attacker could use this flaw to
  bypass those restrictions by using certain command line options and
  symbolic links, allowing the attacker to overwrite those files if they knew
  their file names and had write access to them. (CVE-2007-6200)

  Note: This issue only affected users running rsync as a writable daemon:
  'read only' set to 'false' in the rsync configuration file (for example,
  '/etc/rsyncd.conf'). By default, this option is set to 'true'.

  This update also fixes the following bugs:

  * The rsync package has been upgraded to upstream version 3.0.6, which
  provides a number of bug fixes and enhancements over the previous version.
  (BZ#339971)

  * When running an rsync daemon that was receiving files, a deferred info,
  error or log message could have been sent directly to the sender instead of
  being handled by the 'rwrite()' function in the generator. Also, under
  certain circumstances, a deferred info or error message from the receiver
  could have bypassed the log file and could have been sent only to the
  client process. As a result, an 'unexpected tag 3' fatal error could have
  been displayed. These problems have been fixed in this update so that an
  rsync daemon receiving files now works as expected. (BZ#471182)

  * Prior to this update, the rsync daemon called a number of timezone-using
  functions after doing a chroot. As a result, certain C libraries were
  unable to generate proper timestamps from inside a chrooted daemon. This
  bug has been fixed in this update so that the rsync daemon now calls the
  respective timezone-using functions prior to doing a chroot, and proper
  timestamps are now generated as expected. (BZ#575022)

  * When running rsync under a non-root user with the '-A' ('--acls') option
  and without using the '--numeric-ids' option, if there was an Access
  Control List (ACL) that included a group entry for a group that the
  respective user was not a member of on the receiving side, the
  'acl_set_file()' function returned an invalid argument value ('EINVAL').
  This was caused by rsync mistakenly mapping the group name to the Group ID
  'GID_NONE' ('-1'), which failed. The bug has been fixed in this update so
  that no ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"rsync", rpm:"rsync~3.0.6~4.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
