# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881923");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-04-21 12:02:45 +0530 (Mon, 21 Apr 2014)");
  script_cve_id("CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0451", "CVE-2014-0452",
                "CVE-2014-0453", "CVE-2014-0456", "CVE-2014-0457", "CVE-2014-0458",
                "CVE-2014-0460", "CVE-2014-0461", "CVE-2014-1876", "CVE-2014-2397",
                "CVE-2014-2398", "CVE-2014-2403", "CVE-2014-2412", "CVE-2014-2414",
                "CVE-2014-2421", "CVE-2014-2423", "CVE-2014-2427", "CVE-2013-5797");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for java CESA-2014:0408 centos5");

  script_tag(name:"affected", value:"java on CentOS 5");
  script_tag(name:"insight", value:"The java-1.6.0-openjdk packages provide the OpenJDK 6 Java
Runtime Environment and the OpenJDK 6 Java Software Development Kit.

An input validation flaw was discovered in the medialib library in the 2D
component. A specially crafted image could trigger Java Virtual Machine
memory corruption when processed. A remote attacker, or an untrusted Java
application or applet, could possibly use this flaw to execute arbitrary
code with the privileges of the user running the Java Virtual Machine.
(CVE-2014-0429)

Multiple flaws were discovered in the Hotspot and 2D components in OpenJDK.
An untrusted Java application or applet could use these flaws to trigger
Java Virtual Machine memory corruption and possibly bypass Java sandbox
restrictions. (CVE-2014-0456, CVE-2014-2397, CVE-2014-2421)

Multiple improper permission check issues were discovered in the Libraries
component in OpenJDK. An untrusted Java application or applet could use
these flaws to bypass Java sandbox restrictions. (CVE-2014-0457,
CVE-2014-0461)

Multiple improper permission check issues were discovered in the AWT,
JAX-WS, JAXB, Libraries, and Sound components in OpenJDK. An untrusted Java
application or applet could use these flaws to bypass certain Java sandbox
restrictions. (CVE-2014-2412, CVE-2014-0451, CVE-2014-0458, CVE-2014-2423,
CVE-2014-0452, CVE-2014-2414, CVE-2014-0446, CVE-2014-2427)

Multiple flaws were identified in the Java Naming and Directory Interface
(JNDI) DNS client. These flaws could make it easier for a remote attacker
to perform DNS spoofing attacks. (CVE-2014-0460)

It was discovered that the JAXP component did not properly prevent access
to arbitrary files when a SecurityManager was present. This flaw could
cause a Java application using JAXP to leak sensitive information, or
affect application availability. (CVE-2014-2403)

It was discovered that the Security component in OpenJDK could leak some
timing information when performing PKCS#1 unpadding. This could possibly
lead to the disclosure of some information that was meant to be protected
by encryption. (CVE-2014-0453)

It was discovered that the fix for CVE-2013-5797 did not properly resolve
input sanitization flaws in javadoc. When javadoc documentation was
generated from an untrusted Java source code and hosted on a domain not
controlled by the code author, these issues could make it easier to perform
cross-site scripting (XSS) attacks. (CVE-2014-2398)

An insecure temporary file use flaw was found in the way the unpack200
utility created log files. A local attacker could possibly use this flaw to
perform a symbolic link attack and overwrite arbitrary files with ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:0408");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-April/020258.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~5.1.13.3.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~5.1.13.3.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~5.1.13.3.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~5.1.13.3.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~5.1.13.3.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
