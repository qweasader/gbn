# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-August/msg00008.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870806");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-08-09 10:21:02 +0530 (Thu, 09 Aug 2012)");
  script_cve_id("CVE-2012-2668");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_xref(name:"RHSA", value:"2012:1151-01");
  script_name("RedHat Update for openldap RHSA-2012:1151-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"openldap on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
  Protocol) applications and development tools.

  It was found that the OpenLDAP server daemon ignored olcTLSCipherSuite
  settings. This resulted in the default cipher suite always being used,
  which could lead to weaker than expected ciphers being accepted during
  Transport Layer Security (TLS) negotiation with OpenLDAP clients.
  (CVE-2012-2668)

  This update also fixes the following bug:

  * When the smbk5pwd overlay was enabled in an OpenLDAP server, and a user
  changed their password, the Microsoft NT LAN Manager (NTLM) and Microsoft
  LAN Manager (LM) hashes were not computed correctly. This led to the
  sambaLMPassword and sambaNTPassword attributes being updated with incorrect
  values, preventing the user logging in using a Windows-based client or a
  Samba client.

  Users of OpenLDAP are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. After installing this
  update, the OpenLDAP daemons will be restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"openldap", rpm:"openldap~2.4.23~26.el6_3.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-clients", rpm:"openldap-clients~2.4.23~26.el6_3.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-debuginfo", rpm:"openldap-debuginfo~2.4.23~26.el6_3.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-devel", rpm:"openldap-devel~2.4.23~26.el6_3.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers", rpm:"openldap-servers~2.4.23~26.el6_3.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
