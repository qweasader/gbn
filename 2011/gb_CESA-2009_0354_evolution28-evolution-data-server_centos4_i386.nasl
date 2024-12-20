# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015900.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880940");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2009:0354");
  script_cve_id("CVE-2009-0547", "CVE-2009-0582", "CVE-2009-0587");
  script_name("CentOS Update for evolution28-evolution-data-server CESA-2009:0354 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'evolution28-evolution-data-server'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"evolution28-evolution-data-server on CentOS 4");
  script_tag(name:"insight", value:"Evolution Data Server provides a unified back-end for applications which
  interact with contacts, task, and calendar information. Evolution Data
  Server was originally developed as a back-end for Evolution, but is now
  used by multiple other applications.

  Evolution Data Server did not properly check the Secure/Multipurpose
  Internet Mail Extensions (S/MIME) signatures used for public key encryption
  and signing of e-mail messages. An attacker could use this flaw to spoof a
  signature by modifying the text of the e-mail message displayed to the
  user. (CVE-2009-0547)

  It was discovered that Evolution Data Server did not properly validate NTLM
  (NT LAN Manager) authentication challenge packets. A malicious server using
  NTLM authentication could cause an application using Evolution Data Server
  to disclose portions of its memory or crash during user authentication.
  (CVE-2009-0582)

  Multiple integer overflow flaws which could cause heap-based buffer
  overflows were found in the Base64 encoding routines used by Evolution Data
  Server. This could cause an application using Evolution Data Server to
  crash, or, possibly, execute an arbitrary code when large untrusted data
  blocks were Base64-encoded. (CVE-2009-0587)

  All users of evolution-data-server and evolution28-evolution-data-server
  are advised to upgrade to these updated packages, which contain backported
  patches to correct these issues. All running instances of Evolution Data
  Server and applications using it (such as Evolution) must be restarted for
  the update to take effect.");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"evolution28-evolution-data-server", rpm:"evolution28-evolution-data-server~1.8.0~37.el4_7.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution28-evolution-data-server-devel", rpm:"evolution28-evolution-data-server-devel~1.8.0~37.el4_7.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
