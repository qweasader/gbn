# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2014.25");
  script_cve_id("CVE-2011-1015", "CVE-2011-1521", "CVE-2011-4940", "CVE-2011-4944", "CVE-2012-0845", "CVE-2012-1150", "CVE-2013-4238", "CVE-2014-1912");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DLA-25-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-25-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2014/DLA-25-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python2.6' package(s) announced via the DLA-25-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A regression has been identified in the python2.6 update of DLA-25-1, which may cause python applications to abort if they were running during the upgrade but they had not already imported the 'os' module, and do so after the upgrade. This update fixes this upgrade scenario.

For reference, the original advisory text follows.

Multiple vulnerabilities were discovered in python2.6. The more relevant are:

CVE-2013-4238

Incorrect handling of NUL bytes in certificate hostnames may allow server spoofing via specially-crafted certificates signed by a trusted Certification Authority.

CVE-2014-1912

Buffer overflow in socket.recvfrom_into leading to application crash and possibly code execution.

For Debian 6 Squeeze, these issues have been fixed in python2.6 version 2.6.6-8+deb6u2");

  script_tag(name:"affected", value:"'python2.6' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"idle-python2.6", ver:"2.6.6-8+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpython2.6", ver:"2.6.6-8+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.6", ver:"2.6.6-8+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.6-dbg", ver:"2.6.6-8+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.6-dev", ver:"2.6.6-8+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.6-doc", ver:"2.6.6-8+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.6-examples", ver:"2.6.6-8+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.6-minimal", ver:"2.6.6-8+deb6u1", rls:"DEB6"))) {
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
