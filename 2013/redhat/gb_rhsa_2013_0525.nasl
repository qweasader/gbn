# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-February/msg00063.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45450");
  script_oid("1.3.6.1.4.1.25623.1.0.870910");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-02-22 10:00:40 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2010-4531");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"RHSA", value:"2013:0525-02");
  script_name("RedHat Update for pcsc-lite RHSA-2013:0525-02");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcsc-lite'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"pcsc-lite on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"PC/SC Lite provides a Windows SCard compatible interface for communicating
  with smart cards, smart card readers, and other security tokens.

  A stack-based buffer overflow flaw was found in the way pcsc-lite decoded
  certain attribute values of Answer-to-Reset (ATR) messages. A local
  attacker could use this flaw to execute arbitrary code with the privileges
  of the user running the pcscd daemon (root, by default), by inserting a
  specially-crafted smart card. (CVE-2010-4531)

  This update also fixes the following bugs:

  * Due to an error in the init script, the chkconfig utility did not
  automatically place the pcscd init script after the start of the HAL
  daemon. Consequently, the pcscd service did not start automatically at boot
  time. With this update, the pcscd init script has been changed to
  explicitly start only after HAL is up, thus fixing this bug. (BZ#788474,
  BZ#814549)

  * Because the chkconfig settings and the startup files in the /etc/rc.d/
  directory were not changed during the update described in the
  RHBA-2012:0990 advisory, the user had to update the chkconfig settings
  manually to fix the problem. Now, the chkconfig settings and the startup
  files in the /etc/rc.d/ directory are automatically updated as expected.
  (BZ#834803)

  * Previously, the SCardGetAttrib() function did not work properly and
  always returned the 'SCARD_E_INSUFFICIENT_BUFFER' error regardless of the
  actual buffer size. This update applies a patch to fix this bug and the
  SCardGetAttrib() function now works as expected. (BZ#891852)

  All users of pcsc-lite are advised to upgrade to these updated packages,
  which fix these issues. After installing this update, the pcscd daemon will
  be restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"pcsc-lite", rpm:"pcsc-lite~1.5.2~11.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcsc-lite-debuginfo", rpm:"pcsc-lite-debuginfo~1.5.2~11.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcsc-lite-libs", rpm:"pcsc-lite-libs~1.5.2~11.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
