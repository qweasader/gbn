# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882632");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-01-13 15:05:33 +0100 (Fri, 13 Jan 2017)");
  script_cve_id("CVE-2016-5542", "CVE-2016-5554", "CVE-2016-5573", "CVE-2016-5582",
                "CVE-2016-5597");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for java CESA-2017:0061 centos7");
  script_tag(name:"summary", value:"Check the version of java");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The java-1.6.0-openjdk packages provide the OpenJDK 6 Java Runtime
Environment and the OpenJDK 6 Java Software Development Kit.

Security Fix(es):

  * It was discovered that the Hotspot component of OpenJDK did not properly
check arguments of the System.arraycopy() function in certain cases. An
untrusted Java application or applet could use this flaw to corrupt virtual
machine's memory and completely bypass Java sandbox restrictions.
(CVE-2016-5582)

  * It was discovered that the Hotspot component of OpenJDK did not properly
check received Java Debug Wire Protocol (JDWP) packets. An attacker could
possibly use this flaw to send debugging commands to a Java program running
with debugging enabled if they could make victim's browser send HTTP
requests to the JDWP port of the debugged application. (CVE-2016-5573)

  * It was discovered that the Libraries component of OpenJDK did not
restrict the set of algorithms used for Jar integrity verification. This
flaw could allow an attacker to modify content of the Jar file that used
weak signing key or hash algorithm. (CVE-2016-5542)

Note: After this update, MD2 hash algorithm and RSA keys with less than
1024 bits are no longer allowed to be used for Jar integrity verification
by default. MD5 hash algorithm is expected to be disabled by default in the
future updates. A newly introduced security property
jdk.jar.disabledAlgorithms can be used to control the set of disabled
algorithms.

  * A flaw was found in the way the JMX component of OpenJDK handled
classloaders. An untrusted Java application or applet could use this flaw
to bypass certain Java sandbox restrictions. (CVE-2016-5554)

  * A flaw was found in the way the Networking component of OpenJDK handled
HTTP proxy authentication. A Java application could possibly expose HTTPS
server authentication credentials via a plain text network connection to an
HTTP proxy if proxy asked for authentication. (CVE-2016-5597)

Note: After this update, Basic HTTP proxy authentication can no longer be
used when tunneling HTTPS connection through an HTTP proxy. Newly
introduced system properties jdk.http.auth.proxying.disabledSchemes and
jdk.http.auth.tunneling.disabledSchemes can be used to control which
authentication schemes can be requested by an HTTP proxy when proxying HTTP
and HTTPS connections respectively.");
  script_tag(name:"affected", value:"java on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:0061");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-January/022210.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.41~1.13.13.1.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.41~1.13.13.1.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.41~1.13.13.1.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.41~1.13.13.1.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.41~1.13.13.1.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
