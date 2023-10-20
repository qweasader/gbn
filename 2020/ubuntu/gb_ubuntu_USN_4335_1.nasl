# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844399");
  script_cve_id("CVE-2019-11745", "CVE-2019-11755", "CVE-2019-11757", "CVE-2019-11758", "CVE-2019-11759", "CVE-2019-11760", "CVE-2019-11761", "CVE-2019-11762", "CVE-2019-11763", "CVE-2019-11764", "CVE-2019-15903", "CVE-2019-17005", "CVE-2019-17008", "CVE-2019-17010", "CVE-2019-17011", "CVE-2019-17012", "CVE-2019-17016", "CVE-2019-17017", "CVE-2019-17022", "CVE-2019-17024", "CVE-2019-17026", "CVE-2019-20503", "CVE-2020-6792", "CVE-2020-6793", "CVE-2020-6794", "CVE-2020-6795", "CVE-2020-6798", "CVE-2020-6800", "CVE-2020-6805", "CVE-2020-6806", "CVE-2020-6807", "CVE-2020-6811", "CVE-2020-6812", "CVE-2020-6814", "CVE-2020-6819", "CVE-2020-6820", "CVE-2020-6821", "CVE-2020-6822", "CVE-2020-6825");
  script_tag(name:"creation_date", value:"2020-04-22 03:01:11 +0000 (Wed, 22 Apr 2020)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-01 16:07:00 +0000 (Fri, 01 May 2020)");

  script_name("Ubuntu: Security Advisory (USN-4335-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4335-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4335-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-4335-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Thunderbird. If a user were
tricked in to opening a specially crafted website in a browsing context,
an attacker could potentially exploit these to cause a denial of service,
obtain sensitive information, bypass security restrictions, bypass
same-origin restrictions, conduct cross-site scripting (XSS) attacks, or
execute arbitrary code. (CVE-2019-11757, CVE-2019-11758, CVE-2019-11759,
CVE-2019-11760, CVE-2019-11761, CVE-2019-11762, CVE-2019-11763,
CVE-2019-11764, CVE-2019-17005, CVE-2019-17008, CVE-2019-17010,
CVE-2019-17011, CVE-2019-17012, CVE-2019-17016, CVE-2019-17017,
CVE-2019-17022, CVE-2019-17024, CVE-2019-17026, CVE-2019-20503,
CVE-2020-6798, CVE-2020-6800, CVE-2020-6805, CVE-2020-6806, CVE-2020-6807,
CVE-2020-6812, CVE-2020-6814, CVE-2020-6819, CVE-2020-6820, CVE-2020-6821,
CVE-2020-6825)

It was discovered that NSS incorrectly handled certain memory operations.
A remote attacker could potentially exploit this to cause a denial of
service, or execute arbitrary code. (CVE-2019-11745)

It was discovered that a specially crafted S/MIME message with an inner
encryption layer could be displayed as having a valid signature in some
circumstances, even if the signer had no access to the encrypted message.
An attacker could potentially exploit this to spoof the message author.
(CVE-2019-11755)

A heap overflow was discovered in the expat library in Thunderbird. If a
user were tricked in to opening a specially crafted message, an attacker
could potentially exploit this to cause a denial of service, or execute
arbitrary code. (CVE-2019-15903)

It was discovered that Message ID calculation was based on uninitialized
data. An attacker could potentially exploit this to obtain sensitive
information. (CVE-2020-6792)

Multiple security issues were discovered in Thunderbird. If a user were
tricked in to opening a specially crafted message, an attacker could
potentially exploit these to cause a denial of service, obtain sensitive
information, or execute arbitrary code. (CVE-2020-6793, CVE-2020-6795,
CVE-2020-6822)

It was discovered that if a user saved passwords before Thunderbird 60 and
then later set a primary password, an unencrypted copy of these passwords
would still be accessible. A local user could exploit this to obtain
sensitive information. (CVE-2020-6794)

It was discovered that the Devtools' 'Copy as cURL' feature did not
fully escape website-controlled data. If a user were tricked in to using
the 'Copy as cURL' feature to copy and paste a command with specially
crafted data in to a terminal, an attacker could potentially exploit this
to execute arbitrary commands via command injection. (CVE-2020-6811)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:68.7.0+build1-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS"))) {
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
