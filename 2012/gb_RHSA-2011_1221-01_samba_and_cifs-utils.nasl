# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-August/msg00023.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870708");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-09 10:51:10 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-1678", "CVE-2011-2522", "CVE-2011-2694",
                "CVE-2011-2724", "CVE-2010-0547");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"RHSA", value:"2011:1221-01");
  script_name("RedHat Update for samba and cifs-utils RHSA-2011:1221-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba and cifs-utils'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"samba and cifs-utils on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Samba is a suite of programs used by machines to share files, printers, and
  other information. The cifs-utils package contains utilities for mounting
  and managing CIFS (Common Internet File System) shares.

  A cross-site scripting (XSS) flaw was found in the password change page of
  the Samba Web Administration Tool (SWAT). If a remote attacker could trick
  a user, who was logged into the SWAT interface, into visiting a
  specially-crafted URL, it would lead to arbitrary web script execution in
  the context of the user's SWAT session. (CVE-2011-2694)

  It was found that SWAT web pages did not protect against Cross-Site
  Request Forgery (CSRF) attacks. If a remote attacker could trick a user,
  who was logged into the SWAT interface, into visiting a specially-crafted
  URL, the attacker could perform Samba configuration changes with the
  privileges of the logged in user. (CVE-2011-2522)

  It was found that the fix for CVE-2010-0547, provided in the cifs-utils
  package included in the GA release of Red Hat Enterprise Linux 6, was
  incomplete. The mount.cifs tool did not properly handle share or directory
  names containing a newline character, allowing a local attacker to corrupt
  the mtab (mounted file systems table) file via a specially-crafted CIFS
  share mount request, if mount.cifs had the setuid bit set. (CVE-2011-2724)

  It was found that the mount.cifs tool did not handle certain errors
  correctly when updating the mtab file. If mount.cifs had the setuid bit
  set, a local attacker could corrupt the mtab file by setting a small file
  size limit before running mount.cifs. (CVE-2011-1678)

  Note: mount.cifs from the cifs-utils package distributed by Red Hat does
  not have the setuid bit set. We recommend that administrators do not
  manually set the setuid bit for mount.cifs.

  Red Hat would like to thank the Samba project for reporting CVE-2011-2694
  and CVE-2011-2522, and Dan Rosenberg for reporting CVE-2011-1678. Upstream
  acknowledges Nobuhiro Tsuji of NTT DATA Security Corporation as the
  original reporter of CVE-2011-2694, and Yoshihiro Ishikawa of LAC Co., Ltd.
  as the original reporter of CVE-2011-2522.

  This update also fixes the following bug:

  * If plain text passwords were used ('encrypt passwords = no' in
  '/etc/samba/smb.conf'), Samba clients running the Windows XP or Windows
  Server 2003 operating system may not have been able to access Samba shares
  after installing the Micros ...

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

  if ((res = isrpmvuln(pkg:"cifs-utils", rpm:"cifs-utils~4.8.1~2.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cifs-utils-debuginfo", rpm:"cifs-utils-debuginfo~4.8.1~2.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~3.5.6~86.el6_1.4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.5.6~86.el6_1.4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.5.6~86.el6_1.4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.5.6~86.el6_1.4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~3.5.6~86.el6_1.4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.5.6~86.el6_1.4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-winbind-clients", rpm:"samba-winbind-clients~3.5.6~86.el6_1.4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
