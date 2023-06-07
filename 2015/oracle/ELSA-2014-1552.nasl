# Copyright (C) 2015 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123284");
  script_cve_id("CVE-2014-2532", "CVE-2014-2653");
  script_tag(name:"creation_date", value:"2015-10-06 11:01:44 +0000 (Tue, 06 Oct 2015)");
  script_version("2021-10-15T14:03:21+0000");
  script_tag(name:"last_modification", value:"2021-10-15 14:03:21 +0000 (Fri, 15 Oct 2021)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-19 01:29:00 +0000 (Thu, 19 Jul 2018)");

  script_name("Oracle: Security Advisory (ELSA-2014-1552)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1552");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1552.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the ELSA-2014-1552 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[5.3p1-104]
- ignore SIGXFSZ in postauth monitor child (#1133906)

[5.3p1-103]
- don't try to generate DSA keys in the init script in FIPS mode (#1118735)

[5.3p1-102]
- ignore SIGPIPE in ssh-keyscan (#1108836)

[5.3p1-101]
- ssh-add: fix fatal exit when removing card (#1042519)

[5.3p1-100]
- fix race in backported ControlPersist patch (#953088)

[5.3p1-99.2]
- skip requesting smartcard PIN when removing keys from agent (#1042519)

[5.3p1-98]
- add possibility to autocreate only RSA key into initscript (#1111568)
- fix several issues reported by coverity

[5.3p1-97]
- x11 forwarding - be less restrictive when can't bind to one of available addresses
 (#1027197)
- better fork error detection in audit patch (#1028643)
- fix openssh-5.3p1-x11.patch for non-linux platforms (#1100913)

[5.3p1-96]
- prevent a server from skipping SSHFP lookup (#1081338) CVE-2014-2653
- ignore environment variables with embedded '=' or '\0' characters CVE-2014-2532
- backport ControlPersist option (#953088)
- log when a client requests an interactive session and only sftp is allowed (#997377)
- don't try to load RSA1 host key in FIPS mode (#1009959)
- restore Linux oom_adj setting when handling SIGHUP to maintain behaviour over restart
 (#1010429)
- ssh-keygen -V - relative-specified certificate expiry time should be relative to current time
 (#1022459)

[5.3p1-95]
- adjust the key echange DH groups and ssh-keygen according to SP800-131A (#993580)
- log failed integrity test if /etc/system-fips exists (#1020803)
- backport ECDSA and ECDH support (#1028335)");

  script_tag(name:"affected", value:"'openssh' package(s) on Oracle Linux 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~5.3p1~104.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~5.3p1~104.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~5.3p1~104.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-ldap", rpm:"openssh-ldap~5.3p1~104.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~5.3p1~104.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam_ssh_agent_auth", rpm:"pam_ssh_agent_auth~0.9.3~104.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
