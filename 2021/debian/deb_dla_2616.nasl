# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892616");
  script_cve_id("CVE-2021-21341", "CVE-2021-21342", "CVE-2021-21343", "CVE-2021-21344", "CVE-2021-21345", "CVE-2021-21346", "CVE-2021-21347", "CVE-2021-21348", "CVE-2021-21349", "CVE-2021-21350", "CVE-2021-21351");
  script_tag(name:"creation_date", value:"2021-04-04 03:00:15 +0000 (Sun, 04 Apr 2021)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Debian: Security Advisory (DLA-2616-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2616-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2616-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libxstream-java");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxstream-java' package(s) announced via the DLA-2616-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In XStream there is a vulnerability which may allow a remote attacker to load and execute arbitrary code from a remote host only by manipulating the processed input stream.

The type hierarchies for java.io.InputStream, java.nio.channels.Channel, javax.activation.DataSource and javax.sql.rowsel.BaseRowSet are now blacklisted as well as the individual types com.sun.corba.se.impl.activation.ServerTableEntry, com.sun.tools.javac.processing.JavacProcessingEnvironment$NameProcessIterator, sun.awt.datatransfer.DataTransferer$IndexOrderComparator, and sun.swing.SwingLazyValue. Additionally the internal type Accessor$GetterSetterReflection of JAXB, the internal types MethodGetter$PrivilegedGetter and ServiceFinder$ServiceNameIterator of JAX-WS, all inner classes of javafx.collections.ObservableList and an internal ClassLoader used in a private BCEL copy are now part of the default blacklist and the deserialization of XML containing one of the types will fail. You will have to enable these types by explicit configuration, if you need them.

For Debian 9 stretch, these problems have been fixed in version 1.4.11.1-1+deb9u2.

We recommend that you upgrade your libxstream-java packages.

For the detailed security status of libxstream-java please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libxstream-java' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libxstream-java", ver:"1.4.11.1-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
