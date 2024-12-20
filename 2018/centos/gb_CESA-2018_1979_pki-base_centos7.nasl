# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882916");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-07-04 05:56:21 +0200 (Wed, 04 Jul 2018)");
  script_cve_id("CVE-2018-1080");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:38:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for pki-base CESA-2018:1979 centos7");
  script_tag(name:"summary", value:"Check the version of pki-base");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Public Key Infrastructure (PKI) Core contains fundamental packages
required by Red Hat Certificate System.

Security Fix(es):

  * pki-core: Mishandled ACL configuration in AAclAuthz.java reverses rules
that allow and deny access (CVE-2018-1080)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

This issue was discovered by Fraser Tweedale (Red Hat).

Bug Fix(es):

  * Previously, when ECC keys were enrolled, Certificate Management over CMS
(CMC) authentication failed with a 'TokenException: Unable to insert
certificate into temporary database' error. As a consequence, the
enrollment failed. This update fixes the problem. As a result, the
mentioned bug no longer occurs. (BZ#1550581)

  * Previously, Certificate System used the same enrollment profiles for
issuing RSA and ECC certificates. As a consequence, the key usage extension
in issued certificates did not meet the Common Criteria standard. This
update adds ECC-specific enrollment profiles where the key usage extension
for TLS server and client certificates are different as described in RFC
6960. Additionally, the update changes existing profiles to issue only RSA
certificates. As a result, the key usage extension in ECC certificates now
meets the Common Criteria standard. (BZ#1554726)

  * The Certificate System server rejects saving invalid access control lists
(ACL). As a consequence, when saving an ACL with an empty expression, the
server rejected the update and the pkiconsole utility displayed an
StringIndexOutOfBoundsException error. With this update, the utility
rejects empty ACL expressions. As a result, invalid ACLs cannot be saved
and the error is no longer displayed. (BZ#1557883)

  * Previously, due to a bug in the Certificate System installation
procedure, installing a Key Recovery Authority (KRA) with ECC keys failed.
To fix the problem, the installation process has been updated to handle
both RSA and ECC subsystems automatically. As a result, installing
subsystems with ECC keys no longer fail. (BZ#1581134)

  * Previously, during verification, Certificate System encoded the ECC
public key incorrectly in CMC Certificate Request Message Format (CRMF)
requests. As a consequence, requesting an ECC certificate with Certificate
Management over CMS (CMC) in CRMF failed. The problem has been fixed, and
as a result, CMC CRMF requests using ECC keys work as expected.
(BZ#1585945)

Enhancement(s):

  * The pkispawn man page has been updated and now describes the

  - --skip-configuration and --skip-installation parameters. (BZ#15 ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"pki-base on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"CESA", value:"2018:1979");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-July/022940.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"pki-base", rpm:"pki-base~10.5.1~13.1.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-base-java", rpm:"pki-base-java~10.5.1~13.1.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-ca", rpm:"pki-ca~10.5.1~13.1.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-javadoc", rpm:"pki-javadoc~10.5.1~13.1.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-kra", rpm:"pki-kra~10.5.1~13.1.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-server", rpm:"pki-server~10.5.1~13.1.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-symkey", rpm:"pki-symkey~10.5.1~13.1.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-tools", rpm:"pki-tools~10.5.1~13.1.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-core", rpm:"pki-core~10.5.1~13.1.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}