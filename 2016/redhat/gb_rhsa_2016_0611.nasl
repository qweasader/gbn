# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871595");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-04-13 05:17:00 +0200 (Wed, 13 Apr 2016)");
  script_cve_id("CVE-2015-5370", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2115",
                "CVE-2016-2118");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-27 17:17:00 +0000 (Fri, 27 Sep 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for samba RHSA-2016:0611-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Samba is an open-source implementation of the
Server Message Block (SMB) protocol and the related Common Internet File System
(CIFS) protocol, which allow PC-compatible machines to share files, printers, and
various information.

Security Fix(es):

  * Multiple flaws were found in Samba's DCE/RPC protocol implementation. A
remote, authenticated attacker could use these flaws to cause a denial of
service against the Samba server (high CPU load or a crash) or, possibly,
execute arbitrary code with the permissions of the user running Samba
(root). This flaw could also be used to downgrade a secure DCE/RPC
connection by a man-in-the-middle attacker taking control of an Active
Directory (AD) object and compromising the security of a Samba Active
Directory Domain Controller (DC). (CVE-2015-5370)

Note: While Samba packages as shipped in Red Hat Enterprise Linux do not
support running Samba as an AD DC, this flaw applies to all roles Samba
implements.

  * A protocol flaw, publicly referred to as Badlock, was found in the
Security Account Manager Remote Protocol (MS-SAMR) and the Local Security
Authority (Domain Policy) Remote Protocol (MS-LSAD). Any authenticated
DCE/RPC connection that a client initiates against a server could be used
by a man-in-the-middle attacker to impersonate the authenticated user
against the SAMR or LSA service on the server. As a result, the attacker
would be able to get read/write access to the Security Account Manager
database, and use this to reveal all passwords or any other potentially
sensitive information in that database. (CVE-2016-2118)

  * It was discovered that Samba configured as a Domain Controller would
establish a secure communication channel with a machine using a spoofed
computer name. A remote attacker able to observe network traffic could use
this flaw to obtain session-related information about the spoofed machine.
(CVE-2016-2111)

  * It was found that Samba's LDAP implementation did not enforce integrity
protection for LDAP connections. A man-in-the-middle attacker could use
this flaw to downgrade LDAP connections to use no integrity protection,
allowing them to hijack such connections. (CVE-2016-2112)

  * It was found that Samba did not enable integrity protection for IPC
traffic by default. A man-in-the-middle attacker could use this flaw to
view and modify the data sent between a Samba server and a client.
(CVE-2016-2115)

Red Hat would like to thank the Samba project for reporting these issues.
Upstream acknowledges Jouni Knuutinen (Synopsis) as the original reporter
of CVE-2015-5370  and Stefan Metzmacher (SerNet) as the original reporter
of CVE-2016-2118, CVE-2016-2112, and CVE-2016-2115.");
  script_tag(name:"affected", value:"samba on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:0611-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-April/msg00015.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~3.6.23~30.el6_7", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.6.23~30.el6_7", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.6.23~30.el6_7", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.6.23~30.el6_7", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~3.6.23~30.el6_7", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.6.23~30.el6_7", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-winbind-clients", rpm:"samba-winbind-clients~3.6.23~30.el6_7", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
