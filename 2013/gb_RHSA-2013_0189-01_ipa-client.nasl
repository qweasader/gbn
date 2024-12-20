# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_tag(name:"affected", value:"ipa-client on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Red Hat Identity Management is a centralized authentication, identity
  management and authorization solution for both traditional and cloud-based
  enterprise environments.

  A weakness was found in the way IPA clients communicated with IPA servers
  when initially attempting to join IPA domains. As there was no secure way
  to provide the IPA server's Certificate Authority (CA) certificate to the
  client during a join, the IPA client enrollment process was susceptible to
  man-in-the-middle attacks. This flaw could allow an attacker to obtain
  access to the IPA server using the credentials provided by an IPA client,
  including administrative access to the entire domain if the join was
  performed using an administrator's credentials. (CVE-2012-5484)

  Note: This weakness was only exposed during the initial client join to the
  realm, because the IPA client did not yet have the CA certificate of the
  server. Once an IPA client has joined the realm and has obtained the CA
  certificate of the IPA server, all further communication is secure. If a
  client were using the OTP (one-time password) method to join to the realm,
  an attacker could only obtain unprivileged access to the server (enough to
  only join the realm).

  Red Hat would like to thank Petr Menk for reporting this issue.

  When a fix for this flaw has been applied to the client but not yet the
  server, ipa-client-install, in unattended mode, will fail if you do not
  have the correct CA certificate locally, noting that you must use the
  '--force' option to insecurely obtain the certificate. In interactive mode,
  the certificate will try to be obtained securely from LDAP. If this fails,
  you will be prompted to insecurely download the certificate via HTTP. In
  the same situation when using OTP, LDAP will not be queried and you will be
  prompted to insecurely download the certificate via HTTP.

  Users of ipa-client are advised to upgrade to this updated package, which
  corrects this issue.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-January/msg00042.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870893");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-01-24 09:26:51 +0530 (Thu, 24 Jan 2013)");
  script_cve_id("CVE-2012-5484");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2013:0189-01");
  script_name("RedHat Update for ipa-client RHSA-2013:0189-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ipa-client'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~2.1.3~5.el5_9.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-client-debuginfo", rpm:"ipa-client-debuginfo~2.1.3~5.el5_9.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
