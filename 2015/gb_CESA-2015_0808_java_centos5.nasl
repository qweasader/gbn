# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882165");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-04-16 07:02:37 +0200 (Thu, 16 Apr 2015)");
  script_cve_id("CVE-2005-1080", "CVE-2015-0460", "CVE-2015-0469", "CVE-2015-0477",
                "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0488");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for java CESA-2015:0808 centos5");
  script_tag(name:"summary", value:"Check the version of java");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The java-1.6.0-openjdk packages provide
  the OpenJDK 6 Java Runtime Environment and the OpenJDK 6 Java Software Development Kit.

An off-by-one flaw, leading to a buffer overflow, was found in the font
parsing code in the 2D component in OpenJDK. A specially crafted font file
could possibly cause the Java Virtual Machine to execute arbitrary code,
allowing an untrusted Java application or applet to bypass Java sandbox
restrictions. (CVE-2015-0469)

A flaw was found in the way the Hotspot component in OpenJDK handled
phantom references. An untrusted Java application or applet could use this
flaw to corrupt the Java Virtual Machine memory and, possibly, execute
arbitrary code, bypassing Java sandbox restrictions. (CVE-2015-0460)

A flaw was found in the way the JSSE component in OpenJDK parsed X.509
certificate options. A specially crafted certificate could cause JSSE to
raise an exception, possibly causing an application using JSSE to exit
unexpectedly. (CVE-2015-0488)

A flaw was discovered in the Beans component in OpenJDK. An untrusted Java
application or applet could use this flaw to bypass certain Java sandbox
restrictions. (CVE-2015-0477)

A directory traversal flaw was found in the way the jar tool extracted JAR
archive files. A specially crafted JAR archive could cause jar to overwrite
arbitrary files writable by the user running jar when the archive was
extracted. (CVE-2005-1080, CVE-2015-0480)

It was found that the RSA implementation in the JCE component in OpenJDK
did not follow recommended practices for implementing RSA signatures.
(CVE-2015-0478)

The CVE-2015-0478 issue was discovered by Florian Weimer of Red Hat
Product Security.

All users of java-1.6.0-openjdk are advised to upgrade to these updated
packages, which resolve these issues. All running instances of OpenJDK Java
must be restarted for the update to take effect.");
  script_tag(name:"affected", value:"java on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"CESA", value:"2015:0808");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-April/021073.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.35~1.13.7.1.el5_11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.35~1.13.7.1.el5_11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.35~1.13.7.1.el5_11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.35~1.13.7.1.el5_11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.35~1.13.7.1.el5_11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
