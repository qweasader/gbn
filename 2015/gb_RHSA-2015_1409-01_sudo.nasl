# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871414");
  script_version("2023-07-12T05:05:04+0000");
  script_cve_id("CVE-2014-9680");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:29:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2015-07-23 06:27:26 +0200 (Thu, 23 Jul 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for sudo RHSA-2015:1409-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The sudo packages contain the sudo utility which allows system
administrators to provide certain users with the permission to execute
privileged commands, which are used for system management purposes, without
having to log in as root.

It was discovered that sudo did not perform any checks of the TZ
environment variable value. If sudo was configured to preserve the TZ
environment variable, a local user with privileges to execute commands via
sudo could possibly use this flaw to achieve system state changes not
permitted by the configured commands. (CVE-2014-9680)

Note: The default sudoers configuration in Red Hat Enterprise Linux removes
the TZ variable from the environment in which commands run by sudo are
executed.

This update also fixes the following bugs:

  * Previously, the sudo utility child processes could sometimes become
unresponsive because they ignored the SIGPIPE signal. With this update,
SIGPIPE handler is properly restored in the function that reads passwords
from the user, and the child processes no longer ignore SIGPIPE. As a
result, sudo child processes do not hang in this situation. (BZ#1094548)

  * Prior to this update, the order in which sudo rules were processed did
not honor the user-defined sudoOrder attribute. Consequently, sudo rules
were processed in an undefined order even when the user defined the order
in sudoOrder. The implementation of SSSD support in sudo has been modified
to sort the rules according to the sudoOrder value, and sudo rules are now
sorted in the order defined by the user in sudoOrder. (BZ#1138581)

  * Previously, sudo became unresponsive after the user issued a command when
a sudoers source was mentioned multiple times in the /etc/nsswitch.conf
file. The problem occurred when nsswitch.conf contained, for example, the
'sudoers: files sss sss' entry. The sudoers source processing code has been
fixed to correctly handle multiple instances of the same sudoers source.
As a result, sudo no longer hangs when a sudoers source is mentioned
multiple times in /etc/nsswitch.conf. (BZ#1147498)

In addition, this update adds the following enhancement:

  * The sudo utility now supports I/O logs compressed using the zlib library.
With this update, sudo can generate zlib compressed I/O logs and also
process zlib compressed I/O logs generated by other versions of sudo with
zlib support. (BZ#1106433)

All sudo users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add this
enhancement.");
  script_tag(name:"affected", value:"sudo on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:1409-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-July/msg00028.html");
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

  if ((res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.8.6p3~19.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sudo-debuginfo", rpm:"sudo-debuginfo~1.8.6p3~19.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
