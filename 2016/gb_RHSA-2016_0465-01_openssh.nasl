# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871580");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-03-22 06:12:30 +0100 (Tue, 22 Mar 2016)");
  script_cve_id("CVE-2016-1908", "CVE-2016-3115");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-18 13:51:00 +0000 (Thu, 18 Aug 2022)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for openssh RHSA-2016:0465-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenSSH is OpenBSD's SSH (Secure Shell)
protocol implementation. These packages include the core files necessary for both
the OpenSSH client and server.

It was discovered that the OpenSSH server did not sanitize data received
in requests to enable X11 forwarding. An authenticated client with
restricted SSH access could possibly use this flaw to bypass intended
restrictions. (CVE-2016-3115)

An access flaw was discovered in OpenSSH  the OpenSSH client did not
correctly handle failures to generate authentication cookies for untrusted
X11 forwarding. A malicious or compromised remote X application could
possibly use this flaw to establish a trusted connection to the local X
server, even if only untrusted X11 forwarding was requested.
(CVE-2016-1908)

All openssh users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing this
update, the OpenSSH server daemon (sshd) will be restarted automatically.");
  script_tag(name:"affected", value:"openssh on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:0465-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-March/msg00052.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~6.6.1p1~25.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~6.6.1p1~25.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~6.6.1p1~25.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-debuginfo", rpm:"openssh-debuginfo~6.6.1p1~25.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-keycat", rpm:"openssh-keycat~6.6.1p1~25.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~6.6.1p1~25.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
