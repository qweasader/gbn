# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-October/msg00011.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870501");
  script_version("2024-07-25T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-07-25 05:05:41 +0000 (Thu, 25 Jul 2024)");
  script_tag(name:"creation_date", value:"2011-10-21 16:31:29 +0200 (Fri, 21 Oct 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 14:29:45 +0000 (Wed, 24 Jul 2024)");
  script_xref(name:"RHSA", value:"2011:1380-01");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2011-3389", "CVE-2011-3521", "CVE-2011-3544", "CVE-2011-3547",
                "CVE-2011-3548", "CVE-2011-3551", "CVE-2011-3552", "CVE-2011-3553",
                "CVE-2011-3554", "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3558",
                "CVE-2011-3560");
  script_name("RedHat Update for java-1.6.0-openjdk RHSA-2011:1380-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.6.0-openjdk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"java-1.6.0-openjdk on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"These packages provide the OpenJDK 6 Java Runtime Environment and the
  OpenJDK 6 Software Development Kit.

  A flaw was found in the Java RMI (Remote Method Invocation) registry
  implementation. A remote RMI client could use this flaw to execute
  arbitrary code on the RMI server running the registry. (CVE-2011-3556)

  A flaw was found in the Java RMI registry implementation. A remote RMI
  client could use this flaw to execute code on the RMI server with
  unrestricted privileges. (CVE-2011-3557)

  A flaw was found in the IIOP (Internet Inter-Orb Protocol) deserialization
  code. An untrusted Java application or applet running in a sandbox could
  use this flaw to bypass sandbox restrictions by deserializing
  specially-crafted input. (CVE-2011-3521)

  It was found that the Java ScriptingEngine did not properly restrict the
  privileges of sandboxed applications. An untrusted Java application or
  applet running in a sandbox could use this flaw to bypass sandbox
  restrictions. (CVE-2011-3544)

  A flaw was found in the AWTKeyStroke implementation. An untrusted Java
  application or applet running in a sandbox could use this flaw to bypass
  sandbox restrictions. (CVE-2011-3548)

  An integer overflow flaw, leading to a heap-based buffer overflow, was
  found in the Java2D code used to perform transformations of graphic shapes
  and images. An untrusted Java application or applet running in a sandbox
  could use this flaw to bypass sandbox restrictions. (CVE-2011-3551)

  An insufficient error checking flaw was found in the unpacker for JAR files
  in pack200 format. A specially-crafted JAR file could use this flaw to
  crash the Java Virtual Machine (JVM) or, possibly, execute arbitrary code
  with JVM privileges. (CVE-2011-3554)

  It was found that HttpsURLConnection did not perform SecurityManager checks
  in the setSSLSocketFactory method. An untrusted Java application or applet
  running in a sandbox could use this flaw to bypass connection restrictions
  defined in the policy. (CVE-2011-3560)

  A flaw was found in the way the SSL 3 and TLS 1.0 protocols used block
  ciphers in cipher-block chaining (CBC) mode. An attacker able to perform a
  chosen plain text attack against a connection mixing trusted and untrusted
  data could use this flaw to recover portions of the trusted data sent over
  the connection. (CVE-2011-3389)

  Note: This update mitigates the CVE-2011-3389 issue by splitting the first
  application data record byte to a separate SSL/TLS protocol record. This
  mitigation may cause compatibility issues wi ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~1.23.1.9.10.el5_7", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-debuginfo", rpm:"java-1.6.0-openjdk-debuginfo~1.6.0.0~1.23.1.9.10.el5_7", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~1.23.1.9.10.el5_7", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~1.23.1.9.10.el5_7", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~1.23.1.9.10.el5_7", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~1.23.1.9.10.el5_7", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
