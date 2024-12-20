# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871807");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2017-04-22 06:43:42 +0200 (Sat, 22 Apr 2017)");
  script_cve_id("CVE-2017-3509", "CVE-2017-3511", "CVE-2017-3526", "CVE-2017-3533",
                "CVE-2017-3539", "CVE-2017-3544", "CVE-2016-5542");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for java-1.8.0-openjdk RHSA-2017:1108-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.8.0-openjdk'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The java-1.8.0-openjdk packages provide
  the OpenJDK 8 Java Runtime Environment and the OpenJDK 8 Java Software
  Development Kit.

Security Fix(es):

  * An untrusted library search path flaw was found in the JCE component of
OpenJDK. A local attacker could possibly use this flaw to cause a Java
application using JCE to load an attacker-controlled library and hence
escalate their privileges. (CVE-2017-3511)

  * It was found that the JAXP component of OpenJDK failed to correctly
enforce parse tree size limits when parsing XML document. An attacker able
to make a Java application parse a specially crafted XML document could use
this flaw to make it consume an excessive amount of CPU and memory.
(CVE-2017-3526)

  * It was discovered that the HTTP client implementation in the Networking
component of OpenJDK could cache and re-use an NTLM authenticated
connection in a different security context. A remote attacker could
possibly use this flaw to make a Java application perform HTTP requests
authenticated with credentials of a different user. (CVE-2017-3509)

Note: This update adds support for the 'jdk.ntlm.cache' system property
which, when set to false, prevents caching of NTLM connections and
authentications and hence prevents this issue. However, caching remains
enabled by default.

  * It was discovered that the Security component of OpenJDK did not allow
users to restrict the set of algorithms allowed for Jar integrity
verification. This flaw could allow an attacker to modify content of the
Jar file that used weak signing key or hash algorithm. (CVE-2017-3539)

Note: This updates extends the fix for CVE-2016-5542 released as part of
the RHSA-2016:2079 erratum to no longer allow the MD5 hash algorithm during
the Jar integrity verification by adding it to the
jdk.jar.disabledAlgorithms security property.

  * Newline injection flaws were discovered in FTP and SMTP client
implementations in the Networking component in OpenJDK. A remote attacker
could possibly use these flaws to manipulate FTP or SMTP connections
established by a Java application. (CVE-2017-3533, CVE-2017-3544)

Note: If the web browser plug-in provided by the icedtea-web package was
installed, the issues exposed via Java applets could have been exploited
without user interaction if a user visited a malicious website.

Bug Fix(es):

  * When a method is called using the Java Debug Wire Protocol (JDWP)
'invokeMethod' command in a target Java virtual machine, JDWP creates
global references for every Object that is implied in the method
invocation, as well as for the returned argument of the reference type.
P ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"java-1.8.0-openjdk on
  Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2017:1108-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-April/msg00049.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.131~2.b11.el7_3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-debuginfo", rpm:"java-1.8.0-openjdk-debuginfo~1.8.0.131~2.b11.el7_3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.131~2.b11.el7_3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.131~2.b11.el7_3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
