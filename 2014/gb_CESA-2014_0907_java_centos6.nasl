# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881971");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-07-28 16:34:06 +0530 (Mon, 28 Jul 2014)");
  script_cve_id("CVE-2014-2490", "CVE-2014-4209", "CVE-2014-4216", "CVE-2014-4218",
                "CVE-2014-4219", "CVE-2014-4244", "CVE-2014-4252", "CVE-2014-4262",
                "CVE-2014-4263", "CVE-2014-4266");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for java CESA-2014:0907 centos6");

  script_tag(name:"affected", value:"java on CentOS 6");
  script_tag(name:"insight", value:"The java-1.6.0-openjdk packages provide the OpenJDK 6 Java
Runtime Environment and the OpenJDK 6 Java Software Development Kit.

It was discovered that the Hotspot component in OpenJDK did not properly
verify bytecode from the class files. An untrusted Java application or
applet could possibly use these flaws to bypass Java sandbox restrictions.
(CVE-2014-4216, CVE-2014-4219)

A format string flaw was discovered in the Hotspot component event logger
in OpenJDK. An untrusted Java application or applet could use this flaw to
crash the Java Virtual Machine or, potentially, execute arbitrary code with
the privileges of the Java Virtual Machine. (CVE-2014-2490)

An improper permission check issue was discovered in the Libraries
component in OpenJDK. An untrusted Java application or applet could use
this flaw to bypass Java sandbox restrictions. (CVE-2014-4262)

Multiple flaws were discovered in the JMX, Libraries, Security, and
Serviceability components in OpenJDK. An untrusted Java application or
applet could use these flaws to bypass certain Java sandbox restrictions.
(CVE-2014-4209, CVE-2014-4218, CVE-2014-4252, CVE-2014-4266)

It was discovered that the RSA algorithm in the Security component in
OpenJDK did not sufficiently perform blinding while performing operations
that were using private keys. An attacker able to measure timing
differences of those operations could possibly leak information about the
used keys. (CVE-2014-4244)

The Diffie-Hellman (DH) key exchange algorithm implementation in the
Security component in OpenJDK failed to validate public DH parameters
properly. This could cause OpenJDK to accept and use weak parameters,
allowing an attacker to recover the negotiated key. (CVE-2014-4263)

The CVE-2014-4262 issue was discovered by Florian Weimer of Red Hat
Product Security.

This update also fixes the following bug:

  * Prior to this update, an application accessing an unsynchronized HashMap
could potentially enter an infinite loop and consume an excessive amount of
CPU resources. This update resolves this issue. (BZ#1115580)

All users of java-1.6.0-openjdk are advised to upgrade to these updated
packages, which resolve these issues. All running instances of OpenJDK Java
must be restarted for the update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:0907");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-July/020423.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~6.1.13.4.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~6.1.13.4.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~6.1.13.4.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~6.1.13.4.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~6.1.13.4.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
