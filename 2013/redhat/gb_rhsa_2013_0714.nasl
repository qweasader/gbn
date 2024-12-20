# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.870977");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-04-15 10:11:55 +0530 (Mon, 15 Apr 2013)");
  script_cve_id("CVE-2013-1762");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:C");
  script_name("RedHat Update for stunnel RHSA-2013:0714-01");

  script_xref(name:"RHSA", value:"2013:0714-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-April/msg00011.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'stunnel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"stunnel on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"stunnel is a socket wrapper which can provide SSL (Secure Sockets Layer)
  support to ordinary applications. For example, it can be used in
  conjunction with imapd to create an SSL-secure IMAP server.

  An integer conversion issue was found in stunnel when using Microsoft NT
  LAN Manager (NTLM) authentication with the HTTP CONNECT tunneling method.
  With this configuration, and using stunnel in SSL client mode on a 64-bit
  system, an attacker could possibly execute arbitrary code with the
  privileges of the stunnel process via a man-in-the-middle attack or by
  tricking a user into using a malicious proxy. (CVE-2013-1762)

  All stunnel users should upgrade to this updated package, which contains a
  backported patch to correct this issue.");
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

  if ((res = isrpmvuln(pkg:"stunnel", rpm:"stunnel~4.29~3.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"stunnel-debuginfo", rpm:"stunnel-debuginfo~4.29~3.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
