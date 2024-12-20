# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871328");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-03-06 06:50:21 +0100 (Fri, 06 Mar 2015)");
  script_cve_id("CVE-2014-2653", "CVE-2014-9278");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for openssh RHSA-2015:0425-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenSSH is OpenBSD's SSH (Secure Shell) protocol implementation. These
packages include the core files necessary for both the OpenSSH client and
server.

It was discovered that OpenSSH clients did not correctly verify DNS SSHFP
records. A malicious server could use this flaw to force a connecting
client to skip the DNS SSHFP record check and require the user to perform
manual host verification of the DNS SSHFP record. (CVE-2014-2653)

It was found that when OpenSSH was used in a Kerberos environment, remote
authenticated users were allowed to log in as a different user if they were
listed in the ~/.k5users file of that user, potentially bypassing intended
authentication restrictions. (CVE-2014-9278)

The openssh packages have been upgraded to upstream version 6.6.1, which
provides a number of bug fixes and enhancements over the previous version.
(BZ#1059667)

Bug fixes:

  * An existing /dev/log socket is needed when logging using the syslog
utility, which is not possible for all chroot environments based on the
user's home directories. As a consequence, the sftp commands were not
logged in the chroot setup without /dev/log in the internal sftp subsystem.
With this update, openssh has been enhanced to detect whether /dev/log
exists. If /dev/log does not exist, processes in the chroot environment use
their master processes for logging. (BZ#1083482)

  * The buffer size for a host name was limited to 64 bytes. As a
consequence, when a host name was 64 bytes long or longer, the ssh-keygen
utility failed. The buffer size has been increased to fix this bug, and
ssh-keygen no longer fails in the described situation. (BZ#1097665)

  * Non-ASCII characters have been replaced by their octal representations in
banner messages in order to prevent terminal re-programming attacks.
Consequently, banners containing UTF-8 strings were not correctly displayed
in a client. With this update, banner messages are processed according to
RFC 3454, control characters have been removed, and banners containing
UTF-8 strings are now displayed correctly. (BZ#1104662)

  * Red Hat Enterprise Linux uses persistent Kerberos credential caches,
which are shared between sessions. Previously, the GSSAPICleanupCredentials
option was set to 'yes' by default. Consequently, removing a Kerberos cache
on logout could remove unrelated credentials of other sessions, which could
make the system unusable. To fix this bug, GSSAPICleanupCredentials is set
by default to 'no'. (BZ#1134447)

  * Access permissions for the /etc/ssh/moduli file were set to 0600, which
was unnecessarily strict. With this update, the permissions  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"openssh on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:0425-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-March/msg00014.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~6.6.1p1~11.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~6.6.1p1~11.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~6.6.1p1~11.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-debuginfo", rpm:"openssh-debuginfo~6.6.1p1~11.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-keycat", rpm:"openssh-keycat~6.6.1p1~11.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~6.6.1p1~11.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}