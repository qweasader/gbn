# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882445");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-04-11 12:47:22 +0530 (Mon, 11 Apr 2016)");
  script_cve_id("CVE-2015-8629", "CVE-2015-8630", "CVE-2015-8631");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-21 15:47:00 +0000 (Tue, 21 Jan 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for krb5-devel CESA-2016:0532 centos7");
  script_tag(name:"summary", value:"Check the version of krb5-devel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Kerberos is a network authentication
system, which can improve the security of your network by eliminating the
insecure practice of sending passwords over the network in unencrypted form.
It allows clients and servers to authenticate to each other with the help of a
trusted third party, the Kerberos key distribution center (KDC).

Security Fix(es):

  * A memory leak flaw was found in the krb5_unparse_name() function of the
MIT Kerberos kadmind service. An authenticated attacker could repeatedly
send specially crafted requests to the server, which could cause the server
to consume large amounts of memory resources, ultimately leading to a
denial of service due to memory exhaustion. (CVE-2015-8631)

  * An out-of-bounds read flaw was found in the kadmind service of MIT
Kerberos. An authenticated attacker could send a maliciously crafted
message to force kadmind to read beyond the end of allocated memory, and
write the memory contents to the KDC database if the attacker has write
permission, leading to information disclosure. (CVE-2015-8629)

  * A NULL pointer dereference flaw was found in the procedure used by the
MIT Kerberos kadmind service to store policies: the
kadm5_create_principal_3() and kadm5_modify_principal() function did not
ensure that a policy was given when KADM5_POLICY was set. An authenticated
attacker with permissions to modify the database could use this flaw to add
or modify a principal with a policy set to NULL, causing the kadmind
service to crash. (CVE-2015-8630)

The CVE-2015-8631 issue was discovered by Simo Sorce of Red Hat.");
  script_tag(name:"affected", value:"krb5-devel on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"CESA", value:"2016:0532");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-March/021788.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.13.2~12.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.13.2~12.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-pkinit", rpm:"krb5-pkinit~1.13.2~12.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.13.2~12.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.13.2~12.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.13.2~12.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.13.2~12.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
